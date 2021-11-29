
using System.Buffers;
using System.Net;
using System.Net.Sockets;

QueryServer query = new QueryServer();

query.StartListening(19132);

query.OnReceiveCB = (EndPoint ip, byte[] buffer, int len) =>
{
    Console.WriteLine($"Received from {ip}: {BitConverter.ToString(buffer, 0, len)}");
    return true;
};

Socket s = new Socket(SocketType.Dgram, ProtocolType.Udp);

s.Bind(new IPEndPoint(IPAddress.Loopback, 0));

Socket s2 = new Socket(SocketType.Dgram, ProtocolType.Udp);

s2.Bind(new IPEndPoint(IPAddress.IPv6Loopback, 0));

s.SendTo(new byte[] { 0x42, 0x73, 0x89, 0x42 }, new IPEndPoint(IPAddress.Loopback, 19132));
s2.SendTo(new byte[] { 0x42, 0x73, 0x89, 0x42, 0x02 }, new IPEndPoint(IPAddress.IPv6Loopback, 19132));

Thread.Sleep(1000);

query.StopListening();

/// <summary>
/// Class used to listen for minecraft querys and respond
/// </summary>
class QueryServer
{
    const int MaxListenRetry = 10;

    //Query Protocol
    const ushort Magic = 0xFDFE;

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

            s.Dispose();
        }        
    }

    void HandlePacket(byte[] buffer, int len, EndPoint address)
    {
        ReceiveCallback? cb = OnReceiveCB;

        if (cb is not null)
            if (!cb(address, buffer, len))
                return;


    }

    static void OnReceive(IAsyncResult res)
    {
        QueryServer? server = (QueryServer?)res.AsyncState;

        if (server is null || server.s is null || server.buffer is null)
            return;

        EndPoint ip = new IPEndPoint(IPAddress.IPv6Any, 0);

        int c = server.s.EndReceiveFrom(res, ref ip);

        byte[] buffer = server.buffer;

        server.Listen();

        try
        {
            if (c > 0)
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
            if (c++ < MaxListenRetry)
                goto retry;
        }
    }
}