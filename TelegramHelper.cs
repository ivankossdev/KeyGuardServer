using System;
using System.IO;

namespace KeyGuardServer
{
    public static class TelegramHelper
    {
        private static ushort _refCounter = 0;
        private static readonly object _refLock = new object();
        private const uint SERVER_SRC = 0xF0000005;
        private const byte DEFAULT_VERS = 0;

        public static ushort GetNextRef()
        {
            lock (_refLock)
            {
                if (_refCounter >= 0x7FFF) _refCounter = 0;
                return ++_refCounter;
            }
        }

        public static uint PackTime(DateTime dt)
        {
            int year = dt.Year - 2010;
            if (year < 0) year = 0;
            if (year > 0x3F) year = 0x3F;
            return (uint)(dt.Second | (dt.Minute << 6) | (dt.Hour << 12) |
                          (dt.Day << 17) | (dt.Month << 22) | (year << 26));
        }

        // ==================== ПАРСИНГ ====================
        public static bool ParseTelegram(byte[] telegram, out TelegramHeader header, out byte[]? payload)
        {
            header = default;
            payload = null;

            if (telegram == null || telegram.Length < 36)
                return false;

            int offset = 4;

            header.EncrType = BitConverter.ToUInt16(telegram, offset); offset += 2;
            header.NotUsed = BitConverter.ToUInt16(telegram, offset); offset += 2;
            header.IV = BitConverter.ToUInt32(telegram, offset); offset += 4;
            header.DstReal = BitConverter.ToUInt16(telegram, offset); offset += 2;
            header.Life = telegram[offset]; offset++;
            header.Vers = telegram[offset]; offset++;
            header.Len = BitConverter.ToUInt16(telegram, offset); offset += 2;
            header.Src = BitConverter.ToUInt32(telegram, offset); offset += 4;
            header.Dst = BitConverter.ToUInt32(telegram, offset); offset += 4;
            header.Ref = BitConverter.ToUInt16(telegram, offset); offset += 2;
            header.Bcc = telegram[offset]; offset++;
            header.Cmd = telegram[offset]; offset++;
            header.Ident = telegram[offset]; offset++;
            header.Value = telegram[offset]; offset++;
            header.Time = BitConverter.ToUInt32(telegram, offset); offset += 4;
            header.Acnt = BitConverter.ToUInt32(telegram, offset); offset += 4;

            int payloadLen = header.Len - 32;
            if (payloadLen < 0) return false;

            if (payloadLen > 0)
            {
                payload = new byte[payloadLen];
                Array.Copy(telegram, offset, payload, 0, payloadLen);
            }
            else
            {
                payload = Array.Empty<byte>();
            }

            return true;
        }

        // ==================== ОБЩИЙ МЕТОД ПОСТРОЕНИЯ ====================
        private static byte[] BuildRawTelegram(byte cmd, byte ident, byte value, uint dstSerial, ushort refNum, uint acnt, byte[] payload, byte vers = DEFAULT_VERS, uint src = SERVER_SRC)
        {
            ushort len = (ushort)(32 + payload.Length);
            uint time = 0;

            using (var ms = new MemoryStream())
            {
                ms.Write(new byte[] { 0xA5, 0x5A, 0xB6, 0x6B }, 0, 4);
                ms.Write(BitConverter.GetBytes((ushort)0), 0, 2);
                ms.Write(BitConverter.GetBytes((ushort)0), 0, 2);
                ms.Write(BitConverter.GetBytes((uint)0), 0, 4);
                ms.Write(BitConverter.GetBytes((ushort)0), 0, 2);
                ms.WriteByte(0x80); // life = 128
                ms.WriteByte(vers);
                ms.Write(BitConverter.GetBytes(len), 0, 2);
                ms.Write(BitConverter.GetBytes(src), 0, 4);
                ms.Write(BitConverter.GetBytes(dstSerial), 0, 4);
                ms.Write(BitConverter.GetBytes(refNum), 0, 2);
                ms.WriteByte(0);
                ms.WriteByte(cmd);
                ms.WriteByte(ident);
                ms.WriteByte(value);
                ms.Write(BitConverter.GetBytes(time), 0, 4);
                ms.Write(BitConverter.GetBytes(acnt), 0, 4);
                ms.Write(payload, 0, payload.Length);
                ms.Write(new byte[] { 0xB8, 0x8B, 0xC9, 0x9C }, 0, 4);

                byte[] fullPacket = ms.ToArray();
                byte bcc = 0;
                for (int i = 4; i <= 29; i++)
                    bcc ^= fullPacket[i];
                fullPacket[30] = bcc;
                return fullPacket;
            }
        }

        // ==================== КОМАНДЫ ====================
        public static byte[] BuildCommandTelegram(uint dstSerial, byte ident, byte value, uint acnt = 0, byte[]? payload = null)
        {
            if (payload == null || payload.Length == 0)
                payload = new byte[4] { 0, 0, 0, 0 };
            return BuildRawTelegram(0x81, ident, value, dstSerial, GetNextRef(), acnt, payload);
        }

        public static byte[] BuildDatabaseCommand(uint dstSerial, byte ident, byte value, uint acnt = 0, byte[]? payload = null)
        {
            if (payload == null || payload.Length == 0)
                payload = new byte[4] { 0, 0, 0, 0 };
            return BuildRawTelegram(0x91, ident, value, dstSerial, GetNextRef(), acnt, payload);
        }

        public static byte[] BuildReadCommand(uint dstSerial, byte ident, uint addr, uint acnt = 0)
        {
            byte[] payload = BitConverter.GetBytes(addr);
            return BuildDatabaseCommand(dstSerial, ident, 0xE2, acnt, payload);
        }

        public static byte[] BuildInquiryCommand(uint dstSerial, byte ident, byte value, uint acnt = 0, byte[]? payload = null)
        {
            if (payload == null || payload.Length == 0)
                payload = new byte[4] { 0, 0, 0, 0 };
            return BuildRawTelegram(0x82, ident, value, dstSerial, GetNextRef(), acnt, payload);
        }

        public static byte[] BuildInquiryResponse(uint dstSerial, byte ident, byte value, ushort refNum, uint acnt, byte[] payload)
        {
            return BuildRawTelegram(0x83, ident, value, dstSerial, refNum, acnt, payload);
        }

        public static byte[] BuildWatchDogResponse(uint dstSerial, ushort refNum, uint acnt = 0)
        {
            byte[] payload = new byte[4] { 0, 0, 0, 0 };
            return BuildRawTelegram(0xA3, 0xE5, 0x31, dstSerial, refNum, acnt, payload);
        }

        public static byte[] BuildLogOnCommand(uint dstSerial, uint sysNumber = 0)
        {
            byte[] payload = new byte[16];
            Buffer.BlockCopy(BitConverter.GetBytes(sysNumber), 0, payload, 0, 4);
            return BuildRawTelegram(0xA1, 0xE0, 0xF1, dstSerial, GetNextRef(), 0, payload);
        }

        // ==================== ДОПОЛНИТЕЛЬНЫЕ КОМАНДЫ ====================
        // Подписка (используется при подключении)
        public static byte[] BuildSubscribeCommand(uint dstSerial, uint acnt = 0, byte lastByte = 0x07)
        {
            byte[] payload = new byte[7] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, lastByte };
            return BuildRawTelegram(0x61, 0x01, 0x03, dstSerial, GetNextRef(), acnt, payload);
        }

        // Запрос состояния устройства (Cmd=0xF2, Ident=0x00, Value=0xF0)
        public static byte[] BuildDeviceStateCommand(uint dstSerial, uint acnt = 0)
        {
            byte[] payload = new byte[4] { 0, 0, 0, 0 };
            return BuildRawTelegram(0xF2, 0x00, 0xF0, dstSerial, GetNextRef(), acnt, payload);
        }

        public static byte[] BuildDeviceWriteCommand(uint dstSerial, uint serNumber, uint unitNumber = 1, string name = "KeyGuardDevice")
        {
            byte[] deviceData = new byte[62];
            int offset = 0;
            Buffer.BlockCopy(BitConverter.GetBytes((uint)1), 0, deviceData, offset, 4); offset += 4;
            Buffer.BlockCopy(BitConverter.GetBytes(serNumber), 0, deviceData, offset, 4); offset += 4;
            Buffer.BlockCopy(BitConverter.GetBytes((ushort)0), 0, deviceData, offset, 2); offset += 2;
            Buffer.BlockCopy(BitConverter.GetBytes(unitNumber), 0, deviceData, offset, 4); offset += 4;
            offset += 6;
            offset += 6;
            byte[] nameBytes = System.Text.Encoding.ASCII.GetBytes(name);
            Array.Copy(nameBytes, 0, deviceData, offset, Math.Min(nameBytes.Length, 24));
            offset += 24;
            offset += 2;
            offset += 2;
            offset += 4;
            offset += 1;
            offset += 1;
            offset += 2;
            if (offset != 62) throw new Exception("Invalid device record length");
            return BuildDatabaseCommand(dstSerial, 0x01, 0xE1, 0, deviceData);
        }
    }

    public struct TelegramHeader
    {
        public ushort EncrType;
        public ushort NotUsed;
        public uint IV;
        public ushort DstReal;
        public byte Life;
        public byte Vers;
        public ushort Len;
        public uint Src;
        public uint Dst;
        public ushort Ref;
        public byte Bcc;
        public byte Cmd;
        public byte Ident;
        public byte Value;
        public uint Time;
        public uint Acnt;
    }
}