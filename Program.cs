using System;
using System.Collections.Concurrent;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace KeyGuardTcpServer
{
    class Program
    {
        static async Task Main(string[] args)
        {
            int port = 8000;
            var server = new KeyGuardTcpServer(port);
            var sessions = new ConcurrentDictionary<uint, ClientSession>();
            var cts = new CancellationTokenSource();

            // Обработка Ctrl+C
            Console.CancelKeyPress += (sender, e) =>
            {
                Console.WriteLine("\nПолучен сигнал завершения (Ctrl+C). Остановка сервера...");
                e.Cancel = true;
                cts.Cancel();
            };

            // Подписка на входящие телеграммы
            server.TelegramReceived += async (sender, e) =>
            {
                if (cts.Token.IsCancellationRequested)
                    return;

                if (!TelegramHelper.ParseTelegram(e.Telegram, out var header, out byte[]? payload))
                {
                    Console.WriteLine("Не удалось разобрать телеграмму.");
                    return;
                }

                if (payload is null)
                {
                    Console.WriteLine("Payload is null, хотя парсинг успешен.");
                    return;
                }

                // Сохраняем сессию по серийному номеру устройства
                if (header.Src != 0 && header.Src != 0xF0000000)
                {
                    sessions[header.Src] = e.Session;
                }

                Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] Получена телеграмма от {e.RemoteEndPoint}:");
                Console.WriteLine($"  Cmd=0x{header.Cmd:X2}, Ident=0x{header.Ident:X2}, Value=0x{header.Value:X2}, Ref={header.Ref}, Src=0x{header.Src:X8}, Dst=0x{header.Dst:X8}");
                Console.WriteLine($"  Payload (первые 16 байт): {BitConverter.ToString(payload.Length > 16 ? payload[0..16] : payload)}");

                // ---- WatchDog ----
                if (header.Cmd == 0xA2 && header.Ident == 0xE5 && header.Value == 0x31)
                {
                    Console.WriteLine("  -> Отвечаем на WatchDog");
                    byte[] ack = TelegramHelper.BuildWatchDogResponse(e.Telegram, header.Src, header.Dst, header.Ref);
                    await e.Session.SendAsync(ack);
                }

                // ---- Card Present -> открыть дверцу ----
                if (header.Cmd == 0x80 && header.Ident == 0x03 && header.Value == 0x80)
                {
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

                // ---- Ответ на чтение (Value = 0xE2) ----
                if (header.Cmd == 0x90 && header.Value == 0xE2)
                {
                    Console.WriteLine($"  <- Ответ на чтение (Ident=0x{header.Ident:X2}):");
                    switch (header.Ident)
                    {
                        case 0x0F: // Ключ
                            if (payload.Length >= 54)
                            {
                                uint keyAddr = BitConverter.ToUInt32(payload, 0);
                                ushort unit = BitConverter.ToUInt16(payload, 4);
                                ushort number = BitConverter.ToUInt16(payload, 6);
                                uint keyNumber = BitConverter.ToUInt32(payload, 8);
                                ushort type = BitConverter.ToUInt16(payload, 12);
                                ushort fixTimeRet = BitConverter.ToUInt16(payload, 14);
                                ushort delayRet = BitConverter.ToUInt16(payload, 16);
                                ushort detArm = BitConverter.ToUInt16(payload, 18);
                                // iButton (8 байт, начиная с 20)
                                byte[] ibutton = new byte[8];
                                Array.Copy(payload, 20, ibutton, 0, 8);
                                // Имя (24 байта, начиная с 28)
                                string name = Encoding.ASCII.GetString(payload, 28, 24).TrimEnd('\0');
                                Console.WriteLine($"    Ключ: addr={keyAddr}, unit={unit}, number={number}, keyNumber=0x{keyNumber:X8}, type=0x{type:X4}");
                                Console.WriteLine($"    fixTimeRet={fixTimeRet}, delayRet={delayRet}, detArm={detArm}");
                                Console.WriteLine($"    iButton: {BitConverter.ToString(ibutton)}");
                                Console.WriteLine($"    Название: {name}");
                            }
                            else
                                Console.WriteLine($"    Payload слишком короткий для ключа ({payload.Length} байт)");
                            break;

                        case 0x0E: // Список ключей
                            if (payload.Length >= 36)
                            {
                                uint listAddr = BitConverter.ToUInt32(payload, 0);
                                ushort textIndex = BitConverter.ToUInt16(payload, 4);
                                Console.WriteLine($"    Список ключей: addr={listAddr}, textIndex={textIndex}");
                                Console.Write("    Содержимое: ");
                                for (int i = 0; i < 15; i++)
                                {
                                    ushort item = BitConverter.ToUInt16(payload, 6 + i * 2);
                                    Console.Write($"{item:X4} ");
                                }
                                Console.WriteLine();
                            }
                            else
                                Console.WriteLine($"    Payload слишком короткий для списка ключей ({payload.Length} байт)");
                            break;

                        case 0xFE: // Заголовок
                            if (payload.Length >= 132)
                            {
                                uint addr = BitConverter.ToUInt32(payload, 0);
                                uint confirm = BitConverter.ToUInt32(payload, 4);
                                ushort vers = BitConverter.ToUInt16(payload, 8);
                                ushort subvers = BitConverter.ToUInt16(payload, 10);
                                Console.WriteLine($"    Заголовок: addr={addr}, confirm=0x{confirm:X8}, vers={vers}, subvers={subvers}");
                                Console.WriteLine("    Количество элементов по типам:");
                                for (int i = 0; i < 29; i++)
                                {
                                    uint qty = BitConverter.ToUInt32(payload, 12 + i * 4);
                                    if (qty > 0)
                                        Console.WriteLine($"      Ident [{i,2}] = {qty}");
                                }
                            }
                            else
                                Console.WriteLine($"    Payload слишком короткий для заголовка ({payload.Length} байт)");
                            break;

                        default:
                            Console.WriteLine($"    Данные (первые 32 байта): {BitConverter.ToString(payload.Length > 32 ? payload[0..32] : payload)}");
                            break;
                    }
                }
            };

            server.Start();

            // Запускаем интерактивную консоль
            var consoleTask = InteractiveConsole(sessions, cts.Token);

            Console.WriteLine("Сервер запущен. Для управления введите команду в консоли.");
            Console.WriteLine("Для выхода введите 'exit' или нажмите Ctrl+C.");

            // Ожидаем завершения консольной задачи или отмены
            await Task.WhenAny(consoleTask, Task.Delay(-1, cts.Token));

            if (!cts.Token.IsCancellationRequested)
                cts.Cancel();

            await Task.Delay(100);
            server.Dispose();
            Console.WriteLine("Сервер остановлен.");
        }

        // ========== ИНТЕРАКТИВНАЯ КОНСОЛЬ ==========
        private static async Task InteractiveConsole(ConcurrentDictionary<uint, ClientSession> sessions, CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                Console.WriteLine("\nВведите команду:");
                Console.WriteLine("  open <serial> <reader>        - открыть дверцу");
                Console.WriteLine("  issue <serial> <key>          - выдать ключ");
                Console.WriteLine("  return <serial> <key>         - сдать ключ");
                Console.WriteLine("  readkeylist <serial> <addr>   - прочитать список ключей по адресу");
                Console.WriteLine("  readkey <serial> <addr>       - прочитать ключ по адресу");
                Console.WriteLine("  readallkeys <serial>          - прочитать все ключи (последовательно)");
                Console.WriteLine("  readheader <serial>           - прочитать заголовок БД");
                Console.WriteLine("  list                          - список подключённых устройств");
                Console.WriteLine("  exit                          - выход");

                string? input = Console.ReadLine();
                if (string.IsNullOrEmpty(input)) continue;

                string[] parts = input.Split(' ');
                string command = parts[0].ToLower();

                if (command == "exit")
                {
                    Console.WriteLine("Завершение работы по команде exit.");
                    break;
                }

                if (command == "list")
                {
                    Console.WriteLine("Подключённые устройства (src):");
                    foreach (var kv in sessions)
                        Console.WriteLine($"  {kv.Key:X8} - сессия {kv.Value.Id}");
                    continue;
                }

                // Команды, требующие серийный номер
                if (parts.Length < 2)
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

                // Обработка команд
                switch (command)
                {
                    case "open":
                    case "issue":
                    case "return":
                        if (parts.Length < 3)
                        {
                            Console.WriteLine("Укажите адрес элемента.");
                            break;
                        }
                        uint addr = Convert.ToUInt32(parts[2]);
                        byte cmdIdent = 0, cmdValue = 0;
                        switch (command)
                        {
                            case "open":  cmdIdent = 0x03; cmdValue = 0x35; break;
                            case "issue": cmdIdent = 0x0F; cmdValue = 0x32; break;
                            case "return":cmdIdent = 0x0F; cmdValue = 0x72; break;
                        }
                        byte[] payload = BitConverter.GetBytes(addr);
                        byte[] cmd = TelegramHelper.BuildCommandTelegram(serial, cmdIdent, cmdValue, 0, payload);
                        await session.SendAsync(cmd);
                        Console.WriteLine($"Команда {command} отправлена устройству 0x{serial:X8}");
                        break;

                    case "readkeylist":
                    case "readkey":
                        if (parts.Length < 3)
                        {
                            Console.WriteLine("Укажите адрес (индекс) элемента.");
                            break;
                        }
                        uint readAddr = Convert.ToUInt32(parts[2]);
                        byte ident = command == "readkeylist" ? (byte)0x0E : (byte)0x0F;
                        byte[] readCmd = TelegramHelper.BuildReadCommand(serial, ident, readAddr);
                        await session.SendAsync(readCmd);
                        Console.WriteLine($"Команда чтения {command} отправлена (адрес {readAddr}).");
                        break;

                    case "readallkeys":
                        Console.WriteLine("Начинаем последовательное чтение всех ключей...");
                        await ReadAllKeysAsync(session, serial);
                        break;

                    case "readheader":
                        byte[] headerCmd = TelegramHelper.BuildReadCommand(serial, 0xFE, 1);
                        await session.SendAsync(headerCmd);
                        Console.WriteLine("Команда чтения заголовка отправлена.");
                        break;

                    default:
                        Console.WriteLine($"Неизвестная команда: {command}");
                        break;
                }
            }
        }

        // ========== ЧТЕНИЕ ВСЕХ КЛЮЧЕЙ ПОСЛЕДОВАТЕЛЬНО ==========
        private static async Task ReadAllKeysAsync(ClientSession session, uint serial)
        {
            // Для демонстрации читаем с 1 по 100 (или до ошибки).
            // В реальном проекте лучше получить точное количество из заголовка.
            const int maxKeys = 100;
            for (uint i = 1; i <= maxKeys; i++)
            {
                byte[] readCmd = TelegramHelper.BuildReadCommand(serial, 0x0F, i);
                await session.SendAsync(readCmd);
                Console.WriteLine($"Запрос ключа #{i} отправлен.");
                await Task.Delay(200);
            }
            Console.WriteLine("Цикл чтения завершён.");
        }
    }
}