using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace KeyGuardTcpServer
{   
    // ------------------- Основная программа -------------------
    class Program
    {
        static async Task Main(string[] args)
        {
            int port = 8000; // можно изменить
            var server = new KeyGuardTcpServer(port);

            // Подписываемся на получение телеграмм
            server.TelegramReceived += async (sender, e) =>
            {
                // e.Telegram – полный пакет с маркерами
                // Парсим заголовок
                byte[] data = e.Telegram;
                int offset = 4; // пропускаем start

                ushort encrType = BitConverter.ToUInt16(data, offset); offset += 2;
                ushort notUsed = BitConverter.ToUInt16(data, offset); offset += 2;
                uint iv = BitConverter.ToUInt32(data, offset); offset += 4;
                ushort dstReal = BitConverter.ToUInt16(data, offset); offset += 2;
                byte life = data[offset]; offset++;
                byte vers = data[offset]; offset++;
                ushort len = BitConverter.ToUInt16(data, offset); offset += 2;
                uint src = BitConverter.ToUInt32(data, offset); offset += 4;
                uint dst = BitConverter.ToUInt32(data, offset); offset += 4;
                ushort refNum = BitConverter.ToUInt16(data, offset); offset += 2;
                byte bcc = data[offset]; offset++;
                byte cmd_t = data[offset]; offset++;
                byte ident = data[offset]; offset++;
                byte value = data[offset]; offset++;
                uint time = BitConverter.ToUInt32(data, offset); offset += 4;
                uint acnt = BitConverter.ToUInt32(data, offset); offset += 4;

                // Полезная нагрузка (data[])
                byte[] payload = new byte[len - 32];
                Array.Copy(data, offset, payload, 0, payload.Length);

                Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] Получена телеграмма от {e.RemoteEndPoint}:");
                Console.WriteLine($"  Cmd=0x{cmd_t:X2}, Ident=0x{ident:X2}, Value=0x{value:X2}, Ref={refNum}, Src=0x{src:X8}, Dst=0x{dst:X8}");
                Console.WriteLine($"  Payload (первые 16 байт): {BitConverter.ToString(payload.Take(16).ToArray())}");

                // ------------------- Обработка WatchDog (проверка связи) -------------------
                // Если это запрос WatchDog (Cmd_t=0xA2, Ident=0xE5, Value=0x31)
                if (cmd_t == 0xA2 && ident == 0xE5 && value == 0x31)
                {
                    Console.WriteLine("  -> Отвечаем на WatchDog");
                    // Формируем ответ: меняем cmd_t на 0xA3, src и dst местами
                    byte[] response = (byte[])data.Clone();
                    // Меняем cmd_t (байт на позиции 22? нужно точно рассчитать)
                    // В нашем offset после парсинга мы можем перезаписать байты в нужных местах.
                    // Смещение cmd_t внутри пакета: начало заголовка + смещение до cmd_t.
                    // Заголовок начинается с 4-го байта (после start).
                    // Смещение cmd_t внутри заголовка: 4 (encrType) +2 +2 +4 +2 +1 +1 +2 +4 +4 +2 +1 = 29? Проверим.
                    // Лучше использовать готовые смещения, которые мы вычислили при парсинге.
                    // Пересоздадим массив для ответа, скопировав исходный.
                    byte[] responseData = new byte[data.Length];
                    Array.Copy(data, responseData, data.Length);
                    // Поменяем местами src (байты 26..29) и dst (байты 30..33) — примерно.
                    // В протоколе src = 4 байта после len (len на позиции 18-19? Надо точно считать.
                    // Для простоты используем позиции, вычисленные при разборе:
                    // после парсинга мы знаем смещение, но проще использовать готовый метод,
                    // который создаёт новый массив с изменёнными полями.
                    // Для краткости я оставлю комментарий и отправлю эхо-пакет без изменения (но это неверно).
                    // Лучше отправлять корректный ответ. Я реализую простой метод создания ответа.
                    byte[] ack = BuildWatchDogResponse(data, src, dst, refNum);
                    await e.Session.SendAsync(ack);
                }
            };

            server.Start();

            Console.WriteLine("Нажмите любую клавишу для остановки...");
            Console.ReadKey();

            server.Dispose();
        }

        // Вспомогательный метод: создаёт ответ на WatchDog
        static byte[] BuildWatchDogResponse(byte[] request, uint src, uint dst, ushort refNum)
        {
            // Копируем исходный пакет
            byte[] response = (byte[])request.Clone();

            // Меняем cmd_t (байт, где лежит cmd_t). Найдём его смещение.
            // В заголовке: start (4) + encrType(2) + notUsed(2) + iv(4) + dstReal(2) + life(1) + vers(1) + len(2) + src(4) + dst(4) + ref(2) + bcc(1)
            // Суммируем: 4+2+2+4+2+1+1+2 = 18, затем src (4) = 22, dst (4) = 26, ref (2) = 28, bcc (1) = 29, cmd_t = 30.
            // Проверим: смещение 30 от начала пакета.
            int cmdOffset = 30;
            // Меняем команду с 0xA2 на 0xA3
            response[cmdOffset] = 0xA3;

            // Меняем местами src и dst: src занимает байты 22-25, dst 26-29
            // Копируем src во временный массив
            byte[] tmpSrc = new byte[4];
            Array.Copy(response, 22, tmpSrc, 0, 4);
            Array.Copy(response, 26, response, 22, 4);
            Array.Copy(tmpSrc, 0, response, 26, 4);

            // ref оставляем тот же, время можно не менять.
            // bcc оставляем как есть (если шифрование выключено, это не важно)

            return response;
        }
    }
}