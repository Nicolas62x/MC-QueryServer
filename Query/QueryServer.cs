
using System.Buffers;
using System.Net;
using System.Net.Sockets;

QueryServer query = new QueryServer();

//Class used to listen for minecraft querys and respond with accurate data
class QueryServer
{
    static ArrayPool<byte> Bytes = ArrayPool<byte>.Shared;

    Socket s;
    byte[] buffer;

    //Start listening for any incoming udp packet for the specified port
    public void StartListening(ushort port)
    {
        if (s is not null)
            throw new Exception("should only be called on inactive server");

        s = new Socket(SocketType.Dgram, ProtocolType.Udp);

        s.Bind(new IPEndPoint(IPAddress.IPv6Any, port));
    }

    void Listen()
    {
        buffer = Bytes.Rent(1500);

        s.BeginReceive(buffer, 0, buffer.Length, SocketFlags.None, OnReceive, this);
    }

    static void OnReceive(IAsyncResult res)
    {
        QueryServer? server = (QueryServer?)res.AsyncState;

        if (server is null || server.s is null)
            return;

        int c = server.s.EndReceive(res);

        byte[] buf = server.buffer;

        try
        {

        }
        catch (Exception)
        {
        }
        finally
        {
            Bytes.Return(buf);
        }

    }
}