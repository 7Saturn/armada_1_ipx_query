using System.Net.Sockets;
using System.Net;
using System;
using System.IO; // File loading/saving
using System.Threading; // For Sleep
using System.Text;
using System.Collections.Generic;
using System.Linq; // For Filters and Skips
using ConsoleParameters;
// Verlangt mono-runtime und libmono-system-core4.0-cil unter Ubuntu 14 bzw. Debian 9
// This constructor arbitrarily assigns the local port number.

class Armada1 {
    private string matchID;
    private string mapName;
    private string gameName;
    private int playerCount;
    private int maxPlayerCount;
    private bool closed;
    private bool ongoing;
    private bool password;
    private bool faulty;
    private bool h2h;
    public Armada1 (byte[] payload) {
        if (payload == null || payload.Length < 96) {
            this.matchID = "00000000000000000000000000000000";
            this.mapName = "faulty";
            this.gameName = "Package";
            this.playerCount = 0;
            this.maxPlayerCount = 0;
            this.faulty = true;
        }
        else {
            // The match ID is a UUID, generated anew for each opened lobby.
            byte[] guid = payload.Skip(16).Take(16).ToArray();
            this.matchID = BitConverter.ToString(guid).Replace("-", string.Empty);
            byte[] playerCount = payload.Skip(52).Take(4).ToArray();
            // We will never have the problem, that more than 8 players are
            // present. So the first byte is quite enough to evaluate.
            this.playerCount = playerCount[0];
            byte[] mapName = payload.Skip(76).Take(12).ToArray();
            this.mapName = Helpers.getStringFromBytes(mapName);
            byte[] gameName = payload.Skip(92).ToArray();
            this.gameName = Helpers.getStringFromBytes(gameName);
            // From the desc1 32 bits only the 3rd byte:
            byte desc1_2 = payload.Skip(73).Take(1).ToArray()[0];
            byte maxPlayers = (byte) (desc1_2 & 224);
            maxPlayers = (byte) (maxPlayers / 32);
            if (maxPlayers == 0) {
                maxPlayers = 8;
            }
            this.maxPlayerCount = (int) maxPlayers;
            byte desc1_3 = payload.Skip(74).Take(1).ToArray()[0];
            byte closedNumber = (byte) (desc1_3 & 2);
            this.closed = (closedNumber == 2);
            byte ongoingNumber = (byte) (desc1_3 & 4);
            this.ongoing = (ongoingNumber == 4);
            byte passwordNumber = (byte) (desc1_3 & 32);
            this.password = (passwordNumber == 32);
            byte h2hNumber = (byte) (desc1_3 & 64);
            this.h2h = (h2hNumber == 64);
            this.faulty = false;
        }
    }

    public bool isFaulty () {
        return this.faulty;
    }

    public string getGameName () {
        return this.gameName;
    }

    public string getMapName () {
        return this.mapName;
    }

    public string getmatchID () {
        return this.matchID;
    }

    public int getPlayerCount () {
        return this.playerCount;
    }

    public bool getIsH2H () {
        return this.h2h;
    }

    public int getMaxPlayerCount () {
        return this.maxPlayerCount;
    }

    public string toString () {
        return this.gameName + " (" + this.mapName + ", " + this.playerCount + " player)";
    }

	public static byte[] querySourceSocket () {
        return new byte[2] {4, 0};
    }
	public static byte[] queryDestinationSocket () {
        return new byte[2] {165, 127};
    }
	public static byte[] query () {
        return new byte[32] {0x70, 0x6c, 0x61, 0x79, 0x02, 0x00, 0x0e, 0x00, 0x01, 0x38, 0xf9, 0x76, 0x40, 0x93, 0xd2, 0x11, 0xae, 0x34, 0x00, 0x60, 0x08, 0x95, 0xc7, 0x79, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00};
    }

    public static IPXPackage getArmadaQueryPackage (byte[] sourceNode) {
        IPXPackage armadaQuery = new IPXPackage();
        armadaQuery.setPacketType(IPXPackage.packetTypeEchoProtocol());
        armadaQuery.setDestinationNode(IPXPackage.BroadcastNode());
        armadaQuery.setDestinationSocket(Armada1.queryDestinationSocket());
        armadaQuery.setSourceNode(sourceNode);
        armadaQuery.setSourceSocket(Armada1.querySourceSocket());
        armadaQuery.setPayload(query());
        armadaQuery.setPacketType(IPXPackage.ipxPacket());
        return armadaQuery;
    }

    public string getJsonObject () {
        return
          "{\"playerCount\":"
        + getPlayerCount()
        + ",\"maxPlayerCount\":"
        + getMaxPlayerCount()
        + ",\"gameName\":\""
        + getGameName().Replace("\\", "\\\\").Replace("\"", "\\\"")
        + "\",\"mapName\":\""
        + getMapName().Replace("\\", "\\\\").Replace("\"", "\\\"")
        + "\",\"matchID\":\""
        + getmatchID()
        + "\",\"closed\":"
        + (closed ? "1" : "0")
        + ",\"ongoing\":"
        + (ongoing ? "1" : "0")
        + ",\"password\":"
        + (password ? "1" : "0")
        + ",\"h2h\":"
        + (h2h ? "1" : "0")
        + "}\n";
    }
}

class Helpers {
    public static void dump_bytes (byte[] bytes) {
		foreach (Byte oneByte in bytes) {
			Console.WriteLine(oneByte + " = " + (char) oneByte);
		}
	}
	public static byte[] ConcatByteArray (byte[][] arraylist) {
		List<byte> temp_list = new List<byte>();
		foreach (byte[] block in arraylist) {
			temp_list.AddRange(block);
		}
		return temp_list.ToArray();
	}
    public static string getStringFromBytes (byte[] bytes) {
        Encoding wind1252 = Encoding.GetEncoding(1252);
        Encoding utf8 = Encoding.UTF8;
        string text = "";
        foreach (byte character in bytes) {
            if (character != 0) {
                byte[] utf8Bytes = Encoding.Convert(wind1252, utf8, new byte[1] {character});
                string utf8String = Encoding.UTF8.GetString(utf8Bytes);
                text += utf8String;
            }
        }
        return text;
    }
    public static int getCurrentEpochTime () {
        TimeSpan t = DateTime.UtcNow - new DateTime(1970, 1, 1);
        return (int)t.TotalSeconds;
    }

    public static void writeStringToFile (string contents, string fileName) {
        try {
            StreamWriter sw = new StreamWriter(fileName);
            sw.WriteLine(contents);
            sw.Close();
        }
        catch(Exception e) {
            Console.WriteLine("Exception: " + e.Message);
        }
    }
}

namespace ConsoleParameters{
    class Program {

        private static IPXPackage getRegisterPackage () {
        IPXPackage register = new IPXPackage();
        register.setPacketType(IPXPackage.packetTypeEchoProtocol());
        register.setDestinationNode(IPXPackage.registerNode());
        register.setDestinationSocket(IPXPackage.errorHandlingSocket());
        register.setSourceNode(IPXPackage.registerNode());
        register.setSourceSocket(IPXPackage.errorHandlingSocket());
        return register;
    }

        static void Main(string[] args) {
            ConsoleParameters.InitializeParameters
                ("--",
             new ParameterDefinition[] {
                 new ParameterDefinition
                     ("outputfile",
                      ParameterType.String,
                      false,
                      1,
                      1,
                      true,
                      "This is the file where the query results will end up, formatted as JSON object. Default value is armada_1.json.",
                      delegate(Parameter p) {
                          string filename = p.getStringValues()[0];
                          if (filename.Length > 253) {
                              return "The provided file name is too long. It may be 253 characters long at most.";
                          }
                          return null;
                      }),
                 new ParameterDefinition
                     ("ip",
                      ParameterType.String,
                      false,
                      1,
                      1,
                      true,
                      "The IPv4 address of the RFC 1234 IPX server to be contacted. Default is 127.0.0.1.",
                      delegate(Parameter p) {
                          string ip = p.getStringValues()[0];
                          IPAddress address;
                          if (IPAddress.TryParse(ip, out address)) {
                              /* We only want IPv4. Technically speaking, IPv6
                                 is probably valid, but the implementations out
                                 there only use IPv6... */
                              if (address.AddressFamily == AddressFamily.InterNetwork) {
                                  return null;
                              }
                          }
                          return "The provided IP " + ip + " is not a valid IPv4 address.";
                      }),
                 new ParameterDefinition
                     ("port",
                      ParameterType.Uinteger,
                      false,
                      1,
                      1,
                      true,
                      "The UDP port of the RFC 1234 IPX server to be contacted. Allowed values range from 0 to 65535. If omitted, RFC 1234 default UDP port 213 is assumed and used.",
                      delegate(Parameter p) {
                          uint port = p.getUintegerValues()[0];
                          if (0 <= port && port < 65536) {
                              return null;
                          }
                          else {
                              return "The provided port " + port + " is not valid.";
                          }
                      }),
                 new ParameterDefinition
                     ("continuous",
                      ParameterType.Boolean,
                      false,
                      1,
                      1,
                      false,
                      "If set, Star Trek: Armada matches will be queried for continuously, once per minute. Every time the output file will be overwritten.")
             },
             args,
             "This is a program useful for querying open Star Trek: Armada matches via an RFC 1234 IPX server. It tries to register with the given IPX server and queries Star Trek: Armada matches hosted on the IPX network. All results will be saved to a JSON formatted file.",
             true);
            bool continuously = ConsoleParameters.getParameterByName("continuous").getBoolValue();
            string jsonFileName;
            if (ConsoleParameters.getParameterByName("outputfile").getNumberOfValues() == 0) {
                jsonFileName = "armada_1.json";
            }
            else {
                jsonFileName = ConsoleParameters.getParameterByName("outputfile").getStringValues()[0];
            }
            IPAddress IPXServer;
            if (ConsoleParameters.getParameterByName("ip").getNumberOfValues() == 0) {
               IPXServer = IPAddress.Parse("127.0.0.1");
            }
            else {
                IPXServer = IPAddress.Parse(ConsoleParameters.getParameterByName("ip").getStringValues()[0]);
            }
            int IPXServerPort;
            if (ConsoleParameters.getParameterByName("port").getNumberOfValues() == 0) {
                IPXServerPort = 213;
            }
            else {
                IPXServerPort = (int) ConsoleParameters.getParameterByName("port").getUintegerValues()[0];
            }
            UdpClient udpClientSender = null;
            try {
    			udpClientSender = new UdpClient(AddressFamily.InterNetwork);
    		}
    		catch (SocketException e) {
    			Console.WriteLine("Could not open a local UDP socket.");
    			Console.WriteLine(e);
    			Environment.Exit(4);
    		}
            try {
                IPEndPoint targetEndpoint = new IPEndPoint(IPXServer, IPXServerPort);

                udpClientSender = new UdpClient(AddressFamily.InterNetwork);

                byte[] registerBytes = getRegisterPackage().getPackageBytes();
                udpClientSender.Send(registerBytes, registerBytes.Length, targetEndpoint);
                Thread.Sleep(20); // Give them some time to react
                // This loop should only go one round tops, because only one
                // package should be received (from the IPX server).
                IPXPackage registerAnswer = new IPXPackage();
                try {
                    while (udpClientSender.Available > 0) {
                        // Blocks until a message returns on this socket from a remote
                        // host. But Available already tolds us, there's something in
                        // the buffer for us.
                        Byte[] receiveBytes = udpClientSender.Receive(ref targetEndpoint);
                        registerAnswer = new IPXPackage(receiveBytes);
                        if (registerAnswer.isFaulty()) {
                            Console.WriteLine("Registration failed.");
                            Environment.Exit(2);
                        }
                    }
                }
                catch (Exception e) {
                    Console.WriteLine("Registration failed. Remote host did not answer.");
                    Environment.Exit(2);
                }
                bool first_round = true;
                while (continuously || first_round) {
                    byte [] IPXServerNode = registerAnswer.getDestinationNode();
                    IPXPackage armadaQuery = Armada1.getArmadaQueryPackage(IPXServerNode);
                    byte [] queryBytes = armadaQuery.getPackageBytes();
                    int epochTime = Helpers.getCurrentEpochTime();
                    udpClientSender.Send(queryBytes, queryBytes.Length, targetEndpoint);
                    Thread.Sleep(20);
                    string json = "{\"time\":" + epochTime + ", \"matches\":[\n";
                    bool is_first = true;
                    try {
                        while (udpClientSender.Available > 0) {
                            // This can go on multiple times, depending on how many
                            // game servers are up.
                            Byte[] receiveBytes = udpClientSender.Receive(ref targetEndpoint);
                            IPXPackage serverAnswer = new IPXPackage(receiveBytes);
                            if (!serverAnswer.isFaulty()) {
                                Armada1 gameInfo = new Armada1(serverAnswer.getPayload());
                                if (!gameInfo.isFaulty()) {
                                    if (!is_first) {
                                        // The single objects come as a line, with linebreak.
                                        // We prepend them, because it's easier, logic-wise.
                                        // Works just as well...
                                        json += ",";
                                    }
                                    else {
                                        is_first = false;
                                    }
                                    json += gameInfo.getJsonObject();
                                }
                            }
                        }
                        json += "]}";
                        Helpers.writeStringToFile(json, jsonFileName);
                        if (continuously) {
                            /* Together with the 20 ms from above, those are 60
                               seconds round time. */
                            Thread.Sleep(59980);
                        }
                    }
                    catch (Exception e) {
                        Console.WriteLine("Armada query failed. IPX server could not be reached.");
                        Environment.Exit(2);
                    }
                    first_round = false;
                }
                udpClientSender.Close();
                udpClientSender.Dispose();
            }
            catch (Exception e) {
                Console.WriteLine(e.ToString());
            }
        }

    }
}
class IPXPackage {
	private static byte[] ipxChecksumConst() {
    	// IPX does not calculate checksums, so this is always constant:
        return new byte[2] {255,255};
    }
	// This is basically the minimum length, when the length of the payload is 0.
	public static byte ipxHeaderLength() {
        return 30;
    }
	private static byte[] maxHopCountConst () {
         // Default Transport Control, when not routing
        return new byte[1] {0};
    }

	private static byte[] localNetwork () {
        // We will not work with IPX routers.
	    // So the network communicated with must be the local one:
	    return new byte[4] {0, 0, 0, 0};
    }
	public static byte[] BroadcastNode () {
        return new byte[6] {255,255,255,255,255,255};
    }
	public static byte[] packetTypeEchoProtocol () {
        // Type Echo
        return new byte[1] {2};
    }
	public static byte[] ipxPacket () {
        //Type normal
        return new byte[1] {0};
    }
	public static byte[] registerNode () {
        // Registration uses fake source and destination nodes. If we receive those via
	    // UDP, then it's an attempt to register with us:
	    return new byte[6] {0, 0, 0, 0, 0, 0};
    }
	public static byte[] errorHandlingSocket () {
        // Pings and registrations use this socket:
	    // Everyone is addressed, meaning, even the IPX server will be addressed.
	    return new byte[2] {0, 2};
    }
	private byte[] checksum = ipxChecksumConst();         // 2 const
	private byte[] length;                                // 2 depends on payload. At least 30
	private byte[] transportControl = maxHopCountConst(); // 1 const
    private byte[] packetType;                            // 1
    private byte[] destinationNetwork = localNetwork();   // 4 default is 0x00 0x00 0x00 0x00
    private byte[] destinationNode;                       // 6
    private byte[] destinationSocket;                     // 2
    private byte[] sourceNetwork = localNetwork();        // 4 Default is 0x00 0x00 0x00 0x00
    private byte[] sourceNode;                            // 6
    private byte[] sourceSocket;                          // 2
    private byte[] payload;                               // Depends...
    private bool faulty = false;
	public IPXPackage (byte[] byteStream) {
        if (byteStream == null || byteStream.Length < ipxHeaderLength()) {
            faulty = true;
            return;
        }
		this.checksum = byteStream.Take(2).ToArray();
		if (!checksum.SequenceEqual(ipxChecksumConst())) {
            faulty = true;
		}
		this.length = byteStream.Skip(2).Take(2).ToArray();
		int packageLength = this.length[0] * 256 + this.length[1];
		if (packageLength != byteStream.Length) {
			faulty = true;
		}
        this.transportControl = byteStream.Skip(4).Take(1).ToArray();
        this.packetType = byteStream.Skip(5).Take(1).ToArray();
        this.destinationNetwork = byteStream.Skip(6).Take(4).ToArray();
        this.destinationNode = byteStream.Skip(10).Take(6).ToArray();
        this.destinationSocket = byteStream.Skip(16).Take(2).ToArray();
        this.sourceNetwork = byteStream.Skip(18).Take(4).ToArray();
        this.sourceNode = byteStream.Skip(22).Take(6).ToArray();
        this.sourceSocket = byteStream.Skip(28).Take(2).ToArray();
		payload = byteStream.Skip(ipxHeaderLength()).ToArray();
	}

    public IPXPackage () {
		this.length = new byte[2] {0, ipxHeaderLength()};
        this.packetType = ipxPacket();
        this.destinationNode = registerNode();
        this.destinationSocket = errorHandlingSocket();
        this.sourceNode = BroadcastNode();
        this.sourceSocket = errorHandlingSocket();
        this.payload = new byte[0] {};            //

	}

    public byte[] getPacketType () {
        return this.packetType;
    }
    public void setPacketType (byte type) {
        this.packetType = new byte[1] {type};
    }
    public void setPacketType (byte[] bytes) {
        if (bytes == null || bytes.Length != 1) {
            this.faulty = true;
        }
        else {
            this.packetType = bytes;
        }
    }

    public byte[] getDestinationNode () {
        return this.destinationNode;
    }
    public void setDestinationNode (byte[] bytes) {
        if (bytes == null || bytes.Length != 6) {
            this.faulty = true;
        }
        this.destinationNode = bytes;
    }

    public byte[] getDestinationSocket () {
        return this.destinationSocket;
    }
    public void setDestinationSocket (byte[] bytes) {
        if (bytes == null || bytes.Length != 2) {
            this.faulty = true;
        }
        this.destinationSocket = bytes;
    }

    public byte[] getSourceNode () {
        return this.sourceNode;
    }
    public void setSourceNode (byte[] bytes) {
        if (bytes == null || bytes.Length != 6) {
            this.faulty = true;
        }
        this.sourceNode = bytes;
    }

    public byte[] getSourceSocket () {
        return this.sourceSocket;
    }
    public void setSourceSocket (byte[] bytes) {
        if (bytes == null || bytes.Length != 2) {
            this.faulty = true;
        }
        this.sourceSocket = bytes;
    }

    public byte[] getPayload () {
        if (faulty) {
            return null;
        }
        else {
            return payload;
        }
    }
    public void setPayload (byte[] byteBlock) {
        int maxLength = 65535 - ipxHeaderLength();
        if (byteBlock == null || (byteBlock.Length > maxLength)) {
            this.payload = null;
            this.faulty = true;
            this.length = null;
        }
        else {
            this.payload = byteBlock;
            // Header counts as well, although it is always 30 bytes. And we
            // made sure that we do not run into overflows...
            ushort decLength =
                (ushort) (this.payload.Length + ipxHeaderLength());
            byte lower  = (byte) (decLength % 256);
            decLength  -= lower;
            byte higher = (byte) (decLength / 256);
            this.length = new byte[] {higher, lower};
        }
    }

    public bool isFaulty () {
        return faulty;
    }
    public byte[] getPackageBytes () {
        if (faulty) {
            return null;
        }
        else {
            return Helpers.ConcatByteArray(
                new byte[][] {
                    checksum,
                    length,
                    transportControl,
                    packetType,
                    destinationNetwork,
                    destinationNode,
                    destinationSocket,
                    sourceNetwork,
                    sourceNode,
                    sourceSocket,
                    payload});
        }
    }

}