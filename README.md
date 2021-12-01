# MC-QueryServer
A project to handle minecraft query request

# USAGE

```csharp
QueryServer query = new QueryServer(
    //theses anonimous function can be any function with a prototype of BaseServerInfo function() and BaseServerInfo FullServerInfo()
    () => new QueryServer.BasicServerInfo { 
    MOTD = "A Query Server !", 
    GameType = "Testing", 
    MapName = "None", 
    NumPlayers = "42", 
    MaxPlayers = "69", 
    HostPort = 19132, 
    HostIp = "127.0.0.1" },
    
    () => new QueryServer.FullServerInfo { 
    MOTD = "A Query Server !", 
    GameType = "Testing", 
    GameID = "MINECRAFT", 
    Plugins = "", 
    Players = new string[] { "Nicolas61x", "dadodasyra", "Zelytra" }, 
    Version = "1.18.0", 
    MapName = "None", 
    NumPlayers = "42", 
    MaxPlayers = "69", 
    HostPort = 19132, 
    HostIp = "127.0.0.1" },
    
    //port to listen to
    19132
    );

//run the query server for 60s
Thread.Sleep(60000);

//stop the server (it can be restarted with StartListening)
query.StopListening();
```
