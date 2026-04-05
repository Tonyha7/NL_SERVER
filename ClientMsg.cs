using System;
using System.Text;
using Google.FlatBuffers;

namespace NL_SERVER
{
    public class ClientMsg
    {
        public uint MsgType { get; set; }
        public object Payload { get; set; }
    }

    public class InitMsg
    {
        public string SteamId { get; set; }
    }

    public class ConfigAckMsg
    {
        public uint EntryId { get; set; }
    }

    public class CreateEntryMsg
    {
        public string Name { get; set; }
        public uint EntryType { get; set; }
        public uint ExpectedCount { get; set; }
    }

    public class UpdateEntryMsg
    {
        public uint EntryId { get; set; }
        public uint EntryType { get; set; }
        public string Content { get; set; }
        public string Name { get; set; }
        public uint? Timestamp { get; set; }
    }

    public static class ClientMsgParser
    {
        public static ClientMsg Parse(byte[] data)
        {
            var bb = new ByteBuffer(data);
            int root = bb.GetInt(bb.Position) + bb.Position;
            var tbl = new Table(root, bb);

            uint msgType = ReadUInt(tbl, 4, 0); // field 0 (type)
            int payloadOffset = tbl.__offset(6); // field 1 (payload array)

            if (payloadOffset == 0) return new ClientMsg { MsgType = msgType };

            int vecPos = tbl.__vector(payloadOffset);
            int vecLen = tbl.__vector_len(payloadOffset);
            
            // payload is [ubyte] containing nested flatbuffer
            // but the payload itself is a nested flatbuffer byte array
            int nestedStart = vecPos;
            var nestedBb = new ByteBuffer(data, nestedStart);
            int nestedRoot = nestedBb.GetInt(nestedBb.Position) + nestedBb.Position;
            var innerTbl = new Table(nestedRoot, nestedBb);

            object parsedPayload = null;

            switch (msgType)
            {
                case 0: // Init
                    parsedPayload = new InitMsg { SteamId = ReadString(innerTbl, 4) };
                    break;
                case 10: // ConfigAck
                    parsedPayload = new ConfigAckMsg { EntryId = ReadUInt(innerTbl, 4, 0) };
                    break;
                case 3: // CreateEntry
                    parsedPayload = new CreateEntryMsg
                    {
                        Name = ReadString(innerTbl, 4),
                        EntryType = ReadUInt(innerTbl, 6, 0),
                        ExpectedCount = ReadUInt(innerTbl, 8, 0)
                    };
                    break;
                case 1: // UpdateEntry
                    parsedPayload = new UpdateEntryMsg
                    {
                        EntryId = ReadUInt(innerTbl, 4, 0),
                        EntryType = ReadUInt(innerTbl, 6, 0),
                        Content = ReadString(innerTbl, 8),
                        Name = ReadString(innerTbl, 10),
                        Timestamp = tbl.__offset(12) != 0 ? ReadUInt(innerTbl, 12, 0) : null
                    };
                    break;
            }

            return new ClientMsg { MsgType = msgType, Payload = parsedPayload };
        }

        private static uint ReadUInt(Table t, int offset, uint def)
        {
            int o = t.__offset(offset);
            return o != 0 ? t.bb.GetUint(o + t.bb_pos) : def;
        }

        private static string ReadString(Table t, int offset)
        {
            int o = t.__offset(offset);
            return o != 0 ? t.__string(o + t.bb_pos) : null;
        }
    }
}