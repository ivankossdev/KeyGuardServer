using System;
using System.Collections.Concurrent;
using System.Threading.Tasks;

namespace KeyGuardTcpServer
{
    class Program
    {
        static void Main(string[] args)
        {
            int port = 8000;
            var server = new KeyGuardTcpServer(port);

            var sessions = new ConcurrentDictionary<uint, ClientSession>();

            server.TelegramReceived += async (sender, e) =>
            {
                // Парсим телеграмму (payload может быть null)
                if (!TelegramHelper.ParseTelegram(e.Telegram, out var header, out byte[]? payload))
                {
                    Console.WriteLine("Не удалось разобрать телеграмму.");
                    return;
                }

                // На случай, если payload всё же null (хотя по логике не должно)
                if (payload is null)
                {
                    Console.WriteLine("Payload is null, хотя парсинг успешен.");
                    return;
                }

                // Сохраняем сессию
                if (header.Src != 0 && header.Src != 0xF0000000)
                {
                    sessions[header.Src] = e.Session;
                }

                Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] Получена телеграмма от {e.RemoteEndPoint}:");
                Console.WriteLine($"  Cmd=0x{header.Cmd:X2}, Ident=0x{header.Ident:X2}, Value=0x{header.Value:X2}, Ref={header.Ref}, Src=0x{header.Src:X8}, Dst=0x{header.Dst:X8}");
                Console.WriteLine($"  Payload (первые 16 байт): {BitConverter.ToString(payload.Length > 16 ? payload[0..16] : payload)}");

                // Обработка WatchDog
                if (header.Cmd == 0xA2 && header.Ident == 0xE5 && header.Value == 0x31)
                {
                    Console.WriteLine("  -> Отвечаем на WatchDog");
                    byte[] ack = TelegramHelper.BuildWatchDogResponse(e.Telegram, header.Src, header.Dst, header.Ref);
                    await e.Session.SendAsync(ack);
                }

                // Пример управления: при Card Present открываем дверцу
                if (header.Cmd == 0x80 && header.Ident == 0x03 && header.Value == 0x80)
                {
                    // Проверяем длину payload
                    if (payload.Length >= 4)
                    {
                        uint readerAddr = BitConverter.ToUInt32(payload, 0);
                        Console.WriteLine($"  -> Карта приложена к считывателю {readerAddr}. Открываем дверцу...");

                        byte[] openDoorPayload = BitConverter.GetBytes(readerAddr);
                        byte[] command = TelegramHelper.BuildCommandTelegram(
                            dstSerial: header.Src,
                            ident: 0x03,
                            value: 0x35,
                            acnt: 0,
                            payload: openDoorPayload
                        );

                        await e.Session.SendAsync(command);
                        Console.WriteLine("  -> Команда открытия двери отправлена.");
                    }
                    else
                    {
                        Console.WriteLine("  -> Payload слишком короткий для чтения адреса считывателя.");
                    }
                }
            };

            server.Start();

            // Интерактивная консоль
            _ = Task.Run(() => InteractiveConsole(sessions));

            Console.WriteLine("Нажмите любую клавишу для остановки...");
            Console.ReadKey();

            server.Dispose();
        }

        private static async Task InteractiveConsole(ConcurrentDictionary<uint, ClientSession> sessions)
        {
            while (true)
            {
                Console.WriteLine("\nВведите команду:");
                Console.WriteLine("  open <serial> <reader>  - открыть дверцу (например: open 0x33A4 1)");
                Console.WriteLine("  issue <serial> <key>    - выдать ключ (например: issue 0x33A4 1)");
                Console.WriteLine("  return <serial> <key>   - сдать ключ");
                Console.WriteLine("  list                    - список подключённых устройств");
                Console.WriteLine("  exit                    - выход");

                string? input = Console.ReadLine();
                if (string.IsNullOrEmpty(input)) continue;

                string[] parts = input.Split(' ');
                string command = parts[0].ToLower();

                if (command == "exit") break;

                if (command == "list")
                {
                    Console.WriteLine("Подключённые устройства (src):");
                    foreach (var kv in sessions)
                        Console.WriteLine($"  {kv.Key:X8} - сессия {kv.Value.Id}");
                    continue;
                }

                if (parts.Length < 3)
                {
                    Console.WriteLine("Недостаточно аргументов.");
                    continue;
                }

                string serialStr = parts[1];
                uint serial;
                if (serialStr.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                    serial = Convert.ToUInt32(serialStr.Substring(2), 16);
                else
                    serial = Convert.ToUInt32(serialStr);

                if (!sessions.TryGetValue(serial, out ClientSession? session))
                {
                    Console.WriteLine($"Устройство с серийным номером 0x{serial:X8} не найдено.");
                    continue;
                }

                uint addr = Convert.ToUInt32(parts[2]);

                byte[] payload = BitConverter.GetBytes(addr);
                byte cmdIdent = 0;
                byte cmdValue = 0;

                switch (command)
                {
                    case "open":
                        cmdIdent = 0x03;
                        cmdValue = 0x35;
                        break;
                    case "issue":
                        cmdIdent = 0x0F;
                        cmdValue = 0x32;
                        break;
                    case "return":
                        cmdIdent = 0x0F;
                        cmdValue = 0x72;
                        break;
                    default:
                        Console.WriteLine("Неизвестная команда.");
                        continue;
                }

                byte[] commandBytes = TelegramHelper.BuildCommandTelegram(serial, cmdIdent, cmdValue, 0, payload);
                await session.SendAsync(commandBytes);
                Console.WriteLine($"Команда отправлена устройству 0x{serial:X8}");
            }
        }
    }
}