using System.Net.Sockets;
using System.Net;
using System;
using System.IO; // File loading/saving
using System.Threading; // For Sleep
using System.Text;
using System.Collections.Generic;
using System.Linq; // For Filters and Skips
// Verlangt mono-runtime und libmono-system-core4.0-cil unter Ubuntu 14 bzw. Debian 9
// This constructor arbitrarily assigns the local port number.

class Armada1 {
    private string mapName;
    private string gameName;
    private int playerCount;
    private bool closed;
    private bool ongoing;
    private bool password;
    public Armada1 (byte[] payload) {
        if (payload == null || payload.Length < 96) {
            this.mapName = "faulty";
            this.gameName = "Package";
            this.playerCount = 0;
        }
        else {
            byte[] playerCount = payload.Skip(52).Take(4).ToArray();
            // We will never have the problem, that more than 8 players are
            // present. So the first byte is quite enough to evaluate.
            this.playerCount = playerCount[0];
            byte[] mapName = payload.Skip(76).Take(12).ToArray();
            this.mapName = Helpers.getStringFromBytes(mapName);
            byte[] gameName = payload.Skip(92).ToArray();
            this.gameName = Helpers.getStringFromBytes(gameName);
            // From the desc1 32 bits only the 3rd byte:
            byte desc1_3 = payload.Skip(74).Take(1).ToArray()[0];
            byte closedNumber = (byte) (desc1_3 & 2);
            this.closed = (closedNumber == 2);
            byte ongoingNumber = (byte) (desc1_3 & 4);
            this.ongoing = (ongoingNumber == 4);
            byte passwordNumber = (byte) (desc1_3 & 32);
            this.password = (passwordNumber == 32);
        }
    }

    public string getGameName () {
        return this.gameName;
    }

    public string getMapName () {
        return this.mapName;
    }

    public int getPlayerCount () {
        return this.playerCount;
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
        + ",\"gameName\":\""
        + getGameName().Replace("\\", "\\\\").Replace("\"", "\\\"")
        + "\",\"mapName\":\""
        + getMapName().Replace("\\", "\\\\").Replace("\"", "\\\"")
        + "\",\"closed\":"
        + (closed ? "1" : "0")
        + ",\"ongoing\":"
        + (ongoing ? "1" : "0")
        + ",\"password\":"
        + (password ? "1" : "0")
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
		IPAddress IPXServer = IPAddress.Parse("192.168.0.1");
		int IPXServerPort = 213;
        string jsonFileName = "armada_1.json";
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
            while (udpClientSender.Available > 0) {
                // Blocks until a message returns on this socket from a remote
                // host. But Available already tolds us, there's something in
                // the buffer for us.
                Byte[] receiveBytes = udpClientSender.Receive(ref targetEndpoint);
                registerAnswer = new IPXPackage(receiveBytes);
                if (registerAnswer.isFaulty()) {
                    Console.WriteLine("Registration failed. Number of received bytes: " + receiveBytes.Length);
                    Console.WriteLine("Received:" );
                    Helpers.dump_bytes(receiveBytes);
                    Environment.Exit(2);
                }
            }
            byte [] IPXServerNode = registerAnswer.getDestinationNode();
            IPXPackage armadaQuery = Armada1.getArmadaQueryPackage(IPXServerNode);
            byte [] queryBytes = armadaQuery.getPackageBytes();
            int epochTime = Helpers.getCurrentEpochTime();
            udpClientSender.Send(queryBytes, queryBytes.Length, targetEndpoint);
            Thread.Sleep(20);
            string json = "{\"time\":" + epochTime + ", \"matches\":[\n";
            bool is_first = true;
            while (udpClientSender.Available > 0) {
                // This can go on multiple times, depending on how many
                // game servers are up.
                Byte[] receiveBytes = udpClientSender.Receive(ref targetEndpoint);
                IPXPackage serverAnswer = new IPXPackage(receiveBytes);
                if (!serverAnswer.isFaulty()) {
                    if (!is_first) {
                        // The single objects come as a line, with linebreak.
                        // We prepend them, because it's easier, logic-wise.
                        // Works just as well...
                        json += ",";
                    }
                    else {
                        is_first = false;
                    }
                    Armada1 gameInfo = new Armada1(serverAnswer.getPayload());
                    json += gameInfo.getJsonObject();
                }
            }
            json += "]}";
            Helpers.writeStringToFile(json, jsonFileName);
            udpClientSender.Close();
            udpClientSender.Dispose();
        }  
        catch (Exception e) {
            Console.WriteLine(e.ToString());
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