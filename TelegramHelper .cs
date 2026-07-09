using System;
using System.IO;

namespace KeyGuardTcpServer
{
    public static class TelegramHelper
    {
        private static ushort _refCounter = 0;
        private static readonly object _refLock = new object();

        public static ushort GetNextRef()
        {
            lock (_refLock)
            {
                if (_refCounter >= 0x7FFF) _refCounter = 0;
                return ++_refCounter;
            }
        }

        /// <summary>
        /// Парсит заголовок телеграммы.
        /// </summary>
        /// <param name="telegram">Массив байтов с маркерами.</param>
        /// <param name="header">Разобранный заголовок.</param>
        /// <param name="payload">Полезные данные (может быть null, если длина 0).</param>
        /// <returns>true, если удалось разобрать.</returns>
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
                payload = Array.Empty<byte>(); // или null, но лучше пустой массив
            }

            return true;
        }

        /// <summary>
        /// Сборка команды управления (Cmd_t = 0x81)
        /// </summary>
        public static byte[] BuildCommandTelegram(uint dstSerial, byte ident, byte value, uint acnt = 0, byte[]? payload = null)
        {
            if (payload == null || payload.Length == 0)
                payload = new byte[4] { 0, 0, 0, 0 };

            ushort len = (ushort)(32 + payload.Length);
            ushort refNum = GetNextRef();

            using (var ms = new MemoryStream())
            {
                // Start marker
                ms.Write(new byte[] { 0xA5, 0x5A, 0xB6, 0x6B }, 0, 4);

                // Заголовок
                ms.Write(BitConverter.GetBytes((ushort)0), 0, 2); // encr_type
                ms.Write(BitConverter.GetBytes((ushort)0), 0, 2); // not_used
                ms.Write(BitConverter.GetBytes((uint)0), 0, 4);   // IV
                ms.Write(BitConverter.GetBytes((ushort)0), 0, 2); // dst_real
                ms.WriteByte(0); // life
                ms.WriteByte(0); // vers (без шифрования)
                ms.Write(BitConverter.GetBytes(len), 0, 2);

                ms.Write(BitConverter.GetBytes((uint)0xF0000000), 0, 4); // src (сервер)
                ms.Write(BitConverter.GetBytes(dstSerial), 0, 4); // dst
                ms.Write(BitConverter.GetBytes(refNum), 0, 2);
                ms.WriteByte(0); // bcc
                ms.WriteByte(0x81); // cmd_t = Command
                ms.WriteByte(ident);
                ms.WriteByte(value);
                ms.Write(BitConverter.GetBytes((uint)0), 0, 4); // time (0 = использовать своё)
                ms.Write(BitConverter.GetBytes(acnt), 0, 4);

                ms.Write(payload, 0, payload.Length);

                // End marker
                ms.Write(new byte[] { 0xB8, 0x8B, 0xC9, 0x9C }, 0, 4);

                return ms.ToArray();
            }
        }

        /// <summary>
        /// Ответ на WatchDog (меняем cmd_t на 0xA3 и меняем src/dst местами)
        /// </summary>
        public static byte[] BuildWatchDogResponse(byte[] request, uint src, uint dst, ushort refNum)
        {
            byte[] response = (byte[])request.Clone();

            // cmd_t находится на смещении 30 от начала пакета (после start)
            response[30] = 0xA3;

            // Меняем местами src и dst: src на позиции 22-25, dst на 26-29
            byte[] tmpSrc = new byte[4];
            Array.Copy(response, 22, tmpSrc, 0, 4);
            Array.Copy(response, 26, response, 22, 4);
            Array.Copy(tmpSrc, 0, response, 26, 4);

            return response;
        }
        
        /// <summary>
        /// Формирует команду чтения элемента базы данных.
        /// </summary>
        /// <param name="dstSerial">Серийный номер устройства (src из входящей телеграммы).</param>
        /// <param name="ident">Тип элемента (0x0E для KeyList, 0x0F для Key и т.д.).</param>
        /// <param name="addr">Адрес (индекс) элемента для чтения (начинается с 1).</param>
        /// <param name="acnt">Номер пользователя (если нужен).</param>
        /// <returns>Массив байтов готовой телеграммы.</returns>
        public static byte[] BuildReadCommand(uint dstSerial, byte ident, uint addr, uint acnt = 0)
        {
            byte[] payload = BitConverter.GetBytes(addr);
            return BuildDatabaseCommand(dstSerial, ident, 0xE2, acnt, payload);
        }
        
        /// <summary>
        /// Формирует запрос состояния (Inquiry Single) с Cmd_t = 0x82.
        /// </summary>
        public static byte[] BuildInquiryCommand(uint dstSerial, byte ident, byte value, uint acnt = 0, byte[]? payload = null)
        {
            if (payload == null || payload.Length == 0)
                payload = new byte[4] { 0, 0, 0, 0 };

            ushort len = (ushort)(32 + payload.Length);
            ushort refNum = GetNextRef();

            using (var ms = new MemoryStream())
            {
                // Start marker
                ms.Write(new byte[] { 0xA5, 0x5A, 0xB6, 0x6B }, 0, 4);

                // Заголовок
                ms.Write(BitConverter.GetBytes((ushort)0), 0, 2); // encr_type
                ms.Write(BitConverter.GetBytes((ushort)0), 0, 2); // not_used
                ms.Write(BitConverter.GetBytes((uint)0), 0, 4);   // IV
                ms.Write(BitConverter.GetBytes((ushort)0), 0, 2); // dst_real
                ms.WriteByte(0); // life
                ms.WriteByte(0); // vers
                ms.Write(BitConverter.GetBytes(len), 0, 2);

                ms.Write(BitConverter.GetBytes((uint)0xF0000000), 0, 4); // src (сервер)
                ms.Write(BitConverter.GetBytes(dstSerial), 0, 4); // dst
                ms.Write(BitConverter.GetBytes(refNum), 0, 2);
                ms.WriteByte(0); // bcc
                ms.WriteByte(0x82); // cmd_t = Inquiry Single
                ms.WriteByte(ident);
                ms.WriteByte(value);
                ms.Write(BitConverter.GetBytes((uint)0), 0, 4); // time
                ms.Write(BitConverter.GetBytes(acnt), 0, 4);

                ms.Write(payload, 0, payload.Length);

                // End marker
                ms.Write(new byte[] { 0xB8, 0x8B, 0xC9, 0x9C }, 0, 4);

                return ms.ToArray();
            }
        }


        /// <summary>
        /// 
        /// </summary>
        /// <param name="dstSerial"></param>
        /// <param name="ident"></param>
        /// <param name="value"></param>
        /// <param name="acnt"></param>
        /// <param name="payload"></param>
        /// <returns></returns>
        public static byte[] BuildDatabaseCommand(uint dstSerial, byte ident, byte value, uint acnt = 0, byte[]? payload = null)
        {
            if (payload == null || payload.Length == 0)
                payload = new byte[4] { 0, 0, 0, 0 };

            ushort len = (ushort)(32 + payload.Length);
            ushort refNum = GetNextRef();

            using (var ms = new MemoryStream())
            {
                ms.Write(new byte[] { 0xA5, 0x5A, 0xB6, 0x6B }, 0, 4);

                ms.Write(BitConverter.GetBytes((ushort)0), 0, 2);
                ms.Write(BitConverter.GetBytes((ushort)0), 0, 2);
                ms.Write(BitConverter.GetBytes((uint)0), 0, 4);
                ms.Write(BitConverter.GetBytes((ushort)0), 0, 2);
                ms.WriteByte(0);
                ms.WriteByte(0); //vers
                ms.Write(BitConverter.GetBytes(len), 0, 2);

                ms.Write(BitConverter.GetBytes((uint)0xF0000000), 0, 4);
                ms.Write(BitConverter.GetBytes(dstSerial), 0, 4);
                ms.Write(BitConverter.GetBytes(refNum), 0, 2);
                ms.WriteByte(0);
                ms.WriteByte(0x91); // cmd_t = 0x91 для работы с БД
                ms.WriteByte(ident);
                ms.WriteByte(value);
                ms.Write(BitConverter.GetBytes((uint)0), 0, 4);
                ms.Write(BitConverter.GetBytes(acnt), 0, 4);

                ms.Write(payload, 0, payload.Length);

                ms.Write(new byte[] { 0xB8, 0x8B, 0xC9, 0x9C }, 0, 4);

                return ms.ToArray();
            }
        }

        public static byte[] BuildDeviceInquiryCommand(uint dstSerial, byte ident, byte value, uint acnt = 0, byte[]? payload = null)
        {
            if (payload == null || payload.Length == 0)
                payload = new byte[4] { 0, 0, 0, 0 };

            ushort len = (ushort)(32 + payload.Length);
            ushort refNum = GetNextRef();

            using (var ms = new MemoryStream())
            {
                ms.Write(new byte[] { 0xA5, 0x5A, 0xB6, 0x6B }, 0, 4);
                ms.Write(BitConverter.GetBytes((ushort)0), 0, 2);
                ms.Write(BitConverter.GetBytes((ushort)0), 0, 2);
                ms.Write(BitConverter.GetBytes((uint)0), 0, 4);
                ms.Write(BitConverter.GetBytes((ushort)0), 0, 2);
                ms.WriteByte(0);
                ms.WriteByte(0); //vers
                ms.Write(BitConverter.GetBytes(len), 0, 2);
                ms.Write(BitConverter.GetBytes((uint)0xF0000000), 0, 4);
                ms.Write(BitConverter.GetBytes(dstSerial), 0, 4);
                ms.Write(BitConverter.GetBytes(refNum), 0, 2);
                ms.WriteByte(0);
                ms.WriteByte(0xF2); // Inquiry Single для работы с устройством
                ms.WriteByte(ident);
                ms.WriteByte(value);
                ms.Write(BitConverter.GetBytes((uint)0), 0, 4);
                ms.Write(BitConverter.GetBytes(acnt), 0, 4);
                ms.Write(payload, 0, payload.Length);
                ms.Write(new byte[] { 0xB8, 0x8B, 0xC9, 0x9C }, 0, 4);
                return ms.ToArray();
            }
        }

        public static byte[] BuildDeviceStatusCommand(uint dstSerial)
        {
            byte[] payload = new byte[4] { 0, 0, 0, 0 };
            ushort len = (ushort)(32 + payload.Length);
            ushort refNum = GetNextRef();

            using (var ms = new MemoryStream())
            {
                ms.Write(new byte[] { 0xA5, 0x5A, 0xB6, 0x6B }, 0, 4);

                ms.Write(BitConverter.GetBytes((ushort)0), 0, 2);
                ms.Write(BitConverter.GetBytes((ushort)0), 0, 2);
                ms.Write(BitConverter.GetBytes((uint)0), 0, 4);
                ms.Write(BitConverter.GetBytes((ushort)0), 0, 2);
                ms.WriteByte(0);
                ms.WriteByte(0); //vers 
                ms.Write(BitConverter.GetBytes(len), 0, 2);

                ms.Write(BitConverter.GetBytes((uint)0xF0000000), 0, 4);
                ms.Write(BitConverter.GetBytes(dstSerial), 0, 4);
                ms.Write(BitConverter.GetBytes(refNum), 0, 2);
                ms.WriteByte(0);
                ms.WriteByte(0xF2); // cmd_t = Inquiry Single для устройства
                ms.WriteByte(0x00); // ident
                ms.WriteByte(0xF0); // value = Value_state
                ms.Write(BitConverter.GetBytes((uint)0), 0, 4);
                ms.Write(BitConverter.GetBytes((uint)0), 0, 4);

                ms.Write(payload, 0, payload.Length);

                ms.Write(new byte[] { 0xB8, 0x8B, 0xC9, 0x9C }, 0, 4);

                return ms.ToArray();
            }
        }

        public static byte[] BuildLogOnCommand(uint dstSerial, uint sysNumber = 0)
        {
            byte[] payload = new byte[16]; // 4 байта sys_number + 12 байт IV
            Buffer.BlockCopy(BitConverter.GetBytes(sysNumber), 0, payload, 0, 4);
            // IV заполняем нулями (или можно сгенерировать случайные)
            // В реальном проекте здесь должен быть 12-байтовый вектор инициализации
            // Для теста оставляем нули

            ushort len = (ushort)(32 + payload.Length);
            ushort refNum = GetNextRef();

            using (var ms = new MemoryStream())
            {
                ms.Write(new byte[] { 0xA5, 0x5A, 0xB6, 0x6B }, 0, 4);
                ms.Write(BitConverter.GetBytes((ushort)0), 0, 2);
                ms.Write(BitConverter.GetBytes((ushort)0), 0, 2);
                ms.Write(BitConverter.GetBytes((uint)0), 0, 4);
                ms.Write(BitConverter.GetBytes((ushort)0), 0, 2);
                ms.WriteByte(0);
                ms.WriteByte(0); // vers = 0
                ms.Write(BitConverter.GetBytes(len), 0, 2);
                ms.Write(BitConverter.GetBytes((uint)0xF0000000), 0, 4);
                ms.Write(BitConverter.GetBytes(dstSerial), 0, 4);
                ms.Write(BitConverter.GetBytes(refNum), 0, 2);
                ms.WriteByte(0);
                ms.WriteByte(0xA1); // cmd_t = Command
                ms.WriteByte(0xE0); // Ident = LogOn
                ms.WriteByte(0xF1); // Value = LogOn
                ms.Write(BitConverter.GetBytes((uint)0), 0, 4);
                ms.Write(BitConverter.GetBytes((uint)0), 0, 4);
                ms.Write(payload, 0, payload.Length);
                ms.Write(new byte[] { 0xB8, 0x8B, 0xC9, 0x9C }, 0, 4);
                return ms.ToArray();
            }
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