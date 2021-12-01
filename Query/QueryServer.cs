
using System.Buffers;
using System.Net;
using System.Net.Sockets;

QueryServer query = new QueryServer();

query.StartListening(19132);

query.OnReceiveCB = (EndPoint ip, byte[] buffer, int len) =>
{
    Console.WriteLine($"Received from {ip} ({len}) {BitConverter.ToString(buffer, 0, len)}");
    return true;
};

Socket s = new Socket(SocketType.Dgram, ProtocolType.Udp);

s.Bind(new IPEndPoint(IPAddress.IPv6Any, 0));

s.SendTo(new byte[] { 0xFE, 0xFD, 0x9, 0x42, 0x73, 0x24, 0x69 }, new IPEndPoint(IPAddress.IPv6Loopback, 19132));
Thread.Sleep(200);
s.SendTo(new byte[] { 0xFE, 0xFD, 0x0, 0x42, 0x73, 0x24, 0x69 , 0, 0, 0, 0}, new IPEndPoint(IPAddress.IPv6Loopback, 19132));

Thread.Sleep(5000);

query.StopListening();

/// <summary>
/// Class used to listen for minecraft querys and respond
/// </summary>
class QueryServer
{
    const int MaxSocketRetry = 10;

    //Query Protocol
    const ushort Magic = 0xFEFD;

    static ArrayPool<byte> Bytes = ArrayPool<byte>.Shared;
    
    Socket? s;
    byte[]? buffer;
    EndPoint ep = new IPEndPoint(IPAddress.IPv6Any, 0);
    object StateLock = new object();
    object CallBackLock = new object();

    //Callback that can be use to ip ban, if false is returned the packet will not be processed.
    ReceiveCallback? _receiveCallback;
    public ReceiveCallback? OnReceiveCB
    {
        set
        {
            lock (CallBackLock)
                _receiveCallback = value;
        }

        get
        {
            lock (CallBackLock)
                return _receiveCallback;
        }
    }
    public delegate bool ReceiveCallback(EndPoint Ip, byte[] buffer, int len);

    /// <summary>
    /// Start listening for any incoming udp packet for the specified port
    /// </summary>
    /// <param name="port">the port to listen to</param>
    /// <exception cref="InvalidOperationException">throw if the server is allready running</exception>
    public void StartListening(ushort port)
    {
        lock (StateLock)
        {
            if (s is not null)
                throw new InvalidOperationException("should only be called on inactive server");

            s = new Socket(SocketType.Dgram, ProtocolType.Udp);

            s.Bind(new IPEndPoint(IPAddress.IPv6Any, port));

            Listen();
        }        
    }

    /// <summary>
    /// Shutdown server and dispose socket
    /// </summary>
    /// <exception cref="InvalidOperationException">throw if the server is not running</exception>
    public void StopListening()
    {
        lock (StateLock)
        {
            if (s is null)
                throw new InvalidOperationException("Server is not started");

            Socket tmp = s;
            s = null;
            tmp.Dispose();
        }        
    }

    Random r = new Random();
    PriorityQueue<int, DateTime> TokenExpiration = new PriorityQueue<int, DateTime>();
    Dictionary<int, EndPoint> TokenToEndPoint = new Dictionary<int, EndPoint>();

    object TokenLock = new object();

    void HandlePacket(byte[] buffer, int len, EndPoint address)
    {
        ReceiveCallback? cb = OnReceiveCB;

        if (cb is not null)
            if (!cb(address, buffer, len))
                return;

        int ptr = 0;

        if (buffer[ptr++] != 0xFE || buffer[ptr++] != 0xFD)
            return;

        byte type = buffer[ptr++];

        int session = BitConverter.ToInt32(buffer, ptr);
        ptr += sizeof(int);

        if (TokenExpiration.Count > 0)
            lock (TokenLock)
            {
                while (TokenExpiration.TryPeek(out int token, out DateTime expiration))
                {
                    if (expiration < DateTime.Now)
                    {
                        int tok = TokenExpiration.Dequeue();
                        TokenToEndPoint.Remove(tok);
                    }
                    else
                        break;
                }
            }
        

        switch (type)
        {
            case 9:

                if (len == 7)
                {
                    //generating response and challenge token
                    int token;

                    lock (TokenLock)
                    {
                        do
                        {
                            token = r.Next();
                        }
                        while (TokenToEndPoint.ContainsKey(token));

                        TokenToEndPoint.Add(token, address);
                        TokenExpiration.Enqueue(token, DateTime.Now.AddSeconds(30));
                    }

                    List<byte> response = new List<byte>();
                    
                    response.Add(9);
                    response.AddRange(BitConverter.GetBytes(session));

                    ReadOnlySpan<char> tok = token.ToString().AsSpan();

                    for (int i = 0; i < tok.Length; i++)
                    {
                        response.Add((byte)tok[i]);
                    }

                    response.Add(0);

                    Send(new SendPacket { data = response.ToArray(), ep = address });
                }

                break;

            case 0:

                if (len == 11)
                {
                    if (!CheckToken(buffer, ref ptr, address))
                        return;
                }
                else if (len == 15)
                {
                    if (!CheckToken(buffer, ref ptr, address))
                        return;
                }

                break;
        }
    }

    bool CheckToken(byte[] buffer, ref int ptr, EndPoint address)
    {
        int token = buffer[ptr++] << 24 | buffer[ptr++] << 16 | buffer[ptr++] << 8 | buffer[ptr++];

        lock (TokenLock)
            if (!TokenToEndPoint.TryGetValue(token, out EndPoint? ep) || !ep.Equals(address))
                return false;
        return true;
    }

    struct SendPacket
    {
        public byte[] data;
        public EndPoint ep;
    }

    object SendLock = new object();
    Queue<SendPacket> packets = new Queue<SendPacket>();
    bool Sending = false;

    void Send(SendPacket packet)
    {

        if (s is null)
            throw new NullReferenceException("Socket was null");

        lock (SendLock)
        {
            if (Sending)
            {
                packets.Enqueue(packet);
            }
            else
            {
                int c = 0;
                retry:

                try
                {
                    s.BeginSendTo(packet.data, 0, packet.data.Length, SocketFlags.None, packet.ep, OnSend, this);
                    Sending = true;
                }
                catch (Exception)
                {
                    if (c++ < MaxSocketRetry)
                        goto retry;
                }                
            }
        }

    }

    static void OnSend(IAsyncResult res)
    {
        QueryServer? server = (QueryServer?)res.AsyncState;

        if (server is null || server.s is null)
            return;

        try
        {
            server.s.EndSendTo(res);
        }
        catch (Exception)
        {
        }
        
        lock (server.SendLock)
        {
            if (server.packets.Count > 0)
            {

                SendPacket packet = server.packets.Dequeue();

                int c = 0;
                retry:

                try
                {
                    server.s.BeginSendTo(packet.data, 0, packet.data.Length, SocketFlags.None, packet.ep, OnSend, server);
                }
                catch (Exception)
                {
                    if (c++ < MaxSocketRetry)
                        goto retry;
                }
            }
            else
                server.Sending = false;
        }
    }

    void Listen()
    {
        if (s is null)
            throw new Exception("Server is not listening");

        int c = 0;

        buffer = Bytes.Rent(1500);

        retry:

        try
        {
            s.BeginReceiveFrom(buffer, 0, buffer.Length, SocketFlags.None, ref ep, OnReceive, this);
        }
        catch (Exception)
        {
            if (c++ < MaxSocketRetry)
                goto retry;
        }
    }

    static void OnReceive(IAsyncResult res)
    {
        QueryServer? server = (QueryServer?)res.AsyncState;

        if (server is null || server.s is null || server.buffer is null)
            return;

        EndPoint ip = new IPEndPoint(IPAddress.IPv6Any, 0);

        int c = 0;

        try
        {
            c = server.s.EndReceiveFrom(res, ref ip);
        }
        catch (Exception)
        {
        }

        byte[] buffer = server.buffer;

        server.Listen();

        try
        {
            if (c > 6)
                server.HandlePacket(buffer, c, ip);
        }
        catch (Exception)
        {
        }
        finally
        {
            Bytes.Return(buffer);
        }

    }
}