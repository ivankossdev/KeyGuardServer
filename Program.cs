using System;
using System.Collections.Concurrent;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace KeyGuardServer
{
    class Program
    {
        private static uint _lastAcnt = 0;
        private static readonly ConcurrentDictionary<uint, ClientSession> _sessions = new();

        static async Task Main(string[] args)
        {
            // Если порт 8000 занят, поменяйте на другой (например, 8001)
            int port = 8000;
            var server = new KeyGuardTcpServer(port);
            var cts = new CancellationTokenSource();

            Console.CancelKeyPress += (sender, e) =>
            {
                Console.WriteLine("\nПолучен сигнал завершения (Ctrl+C). Остановка сервера...");
                e.Cancel = true;
                cts.Cancel();
            };

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

                if (header.Acnt != 0)
                    _lastAcnt = header.Acnt;

                // Сохраняем сессию по src устройства
                if (header.Src != 0 && (header.Src & 0xF0000000) != 0xF0000000) // только устройство, не сервер
                {
                    bool isNew = _sessions.TryAdd(header.Src, e.Session);
                    if (isNew)
                    {
                        Console.WriteLine($"  -> Новая сессия для устройства 0x{header.Src:X8}");
                        // Отправляем подписку при первом подключении
                        Console.WriteLine("  -> Отправляем команду подписки...");
                        byte[] subCmd = TelegramHelper.BuildSubscribeCommand(header.Src, 0);
                        await e.Session.SendAsync(subCmd);
                        Console.WriteLine("  -> Подписка отправлена.");
                    }
                    else
                    {
                        _sessions[header.Src] = e.Session; // обновляем
                        Console.WriteLine($"  -> Сессия для устройства 0x{header.Src:X8} обновлена");
                    }
                }

                Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] Получена телеграмма от {e.RemoteEndPoint}:");
                Console.WriteLine($"  Cmd=0x{header.Cmd:X2}, Ident=0x{header.Ident:X2}, Value=0x{header.Value:X2}, Ref={header.Ref}, Src=0x{header.Src:X8}, Dst=0x{header.Dst:X8}");
                Console.WriteLine($"  Payload (первые 16 байт): {BitConverter.ToString(payload.Length > 16 ? payload[0..16] : payload)}");
                Console.WriteLine($"  Acnt=0x{header.Acnt:X8}");

                // ---- WatchDog ----
                if (header.Cmd == 0xA2 && header.Ident == 0xE5 && header.Value == 0x31)
                {
                    Console.WriteLine("  -> Отвечаем на WatchDog");
                    byte[] ack = TelegramHelper.BuildWatchDogResponse(header.Src, header.Ref, _lastAcnt);
                    await e.Session.SendAsync(ack);
                }

                // ---- LogOn ответ ----
                if (header.Cmd == 0xA0 && header.Ident == 0xE0 && header.Value == 0xF1)
                    Console.WriteLine("  <- LogOn подтверждён устройством");
                if (header.Cmd == 0xA6 && header.Ident == 0xE0 && header.Value == 0xF1)
                    Console.WriteLine("  <- LogOn отклонён (NAC)");

                // ---- Ответ на запрос состояния устройства (Cmd=0xF3) ----
                if (header.Cmd == 0xF3 && header.Ident == 0x00 && header.Value == 0xF0)
                {
                    Console.WriteLine("  <- Ответ на запрос состояния устройства (Cmd=0xF3):");
                    if (payload.Length >= 32)
                    {
                        uint sysNumber = BitConverter.ToUInt32(payload, 0);
                        uint number = BitConverter.ToUInt32(payload, 4);
                        uint serNumber = BitConverter.ToUInt32(payload, 8);
                        ushort type = BitConverter.ToUInt16(payload, 12);
                        byte version = payload[14];
                        byte subversion = payload[15];
                        string name = Encoding.ASCII.GetString(payload, 16, 20).TrimEnd('\0');
                        Console.WriteLine($"    Система: {sysNumber}, Номер: {number}, Серийный: 0x{serNumber:X8}");
                        Console.WriteLine($"    Тип: 0x{type:X4}, Версия: {version}.{subversion}, Имя: {name}");
                    }
                    else
                    {
                        Console.WriteLine($"    Payload слишком короткий ({payload.Length} байт)");
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
                                byte[] ibutton = new byte[8];
                                Array.Copy(payload, 20, ibutton, 0, 8);
                                string name = Encoding.ASCII.GetString(payload, 28, 24).TrimEnd('\0');
                                Console.WriteLine($"    Ключ: addr={keyAddr}, unit={unit}, number={number}, keyNumber=0x{keyNumber:X8}, type=0x{type:X4}");
                                Console.WriteLine($"    fixTimeRet={fixTimeRet}, delayRet={delayRet}, detArm={detArm}");
                                Console.WriteLine($"    iButton: {BitConverter.ToString(ibutton)}");
                                Console.WriteLine($"    Название: {name}");
                            }
                            else
                                Console.WriteLine($"    Payload слишком короткий для ключа ({payload.Length} байт)");
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

                // ---- Ответ на запрос неизвестных ключей ----
                if ((header.Cmd == 0x83 || header.Cmd == 0x85) && header.Ident == 0x0F && header.Value == 0x73)
                {
                    if (payload.Length >= 14)
                    {
                        uint addr = BitConverter.ToUInt32(payload, 0);
                        byte module = payload[4];
                        byte cell = payload[5];
                        byte[] ibutton = new byte[8];
                        Array.Copy(payload, 6, ibutton, 0, 8);
                        Console.WriteLine($"    Неизвестный ключ: addr={addr}, module={module}, cell={cell}, iButton={BitConverter.ToString(ibutton)}");
                    }
                    else
                        Console.WriteLine($"    Payload слишком короткий для неизвестного ключа ({payload.Length} байт)");
                }

                // ---- Подтверждение записи ----
                if (header.Cmd == 0x90 && header.Value == 0xE1)
                {
                    Console.WriteLine($"  <- Подтверждение записи (Ident=0x{header.Ident:X2})");
                    if (payload.Length >= 4)
                    {
                        uint addr = BitConverter.ToUInt32(payload, 0);
                        Console.WriteLine($"    Запись выполнена для элемента с адресом {addr}");
                    }
                }

                // ---- Ответ на запрос состояния клиентов ----
                if (header.Cmd == 0x65 && header.Ident == 0x01 && header.Value == 0x08)
                {
                    Console.WriteLine("  <- Ответ на запрос состояния клиентов (Cmd=0x65)");
                    // payload может содержать структуру, но пока просто выведем
                    Console.WriteLine($"    Payload: {BitConverter.ToString(payload)}");
                }
            };

            server.Start();

            var consoleTask = InteractiveConsole(cts.Token);

            Console.WriteLine("Сервер запущен. Доступные команды:");
            Console.WriteLine("  list                     - список подключённых устройств");
            Console.WriteLine("  state                    - запросить состояние устройства (авто с подпиской)");
            Console.WriteLine("  clientstate <serial>     - запросить состояние клиентов (Cmd=0x65)");
            Console.WriteLine("  logon <serial> [sysNum]  - отправить LogOn (sysNum по умолчанию 0)");
            Console.WriteLine("  readheader <serial>      - прочитать заголовок БД");
            Console.WriteLine("  readkey <serial> <addr>  - прочитать ключ по адресу");
            Console.WriteLine("  unknown <serial>         - запросить незарегистрированные ключи");
            Console.WriteLine("  subscribe <serial>       - отправить подписку вручную");
            Console.WriteLine("  exit                     - выход");

            await Task.WhenAny(consoleTask, Task.Delay(-1, cts.Token));

            if (!cts.Token.IsCancellationRequested)
                cts.Cancel();

            await Task.Delay(100);
            server.Dispose();
            Console.WriteLine("Сервер остановлен.");
        }

        private static async Task InteractiveConsole(CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                Console.Write("\n> ");
                var readTask = Task.Run(() => Console.ReadLine());
                var completedTask = await Task.WhenAny(readTask, Task.Delay(-1, cancellationToken));

                if (completedTask == readTask)
                {
                    string? input = await readTask;
                    if (string.IsNullOrEmpty(input)) continue;

                    string[] parts = input.Split(' ');
                    string command = parts[0].ToLower();

                    if (command == "exit") break;

                    if (command == "list")
                    {
                        Console.WriteLine("Подключённые устройства (src):");
                        foreach (var kv in _sessions)
                            Console.WriteLine($"  {kv.Key:X8} - сессия {kv.Value.Id}");
                        continue;
                    }

                    if (parts.Length < 2)
                    {
                        Console.WriteLine("Недостаточно аргументов. Укажите серийный номер устройства.");
                        continue;
                    }

                    string serialStr = parts[1];
                    uint serial;
                    if (serialStr.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                        serial = Convert.ToUInt32(serialStr.Substring(2), 16);
                    else
                        serial = Convert.ToUInt32(serialStr);

                    if (!_sessions.TryGetValue(serial, out ClientSession? session))
                    {
                        Console.WriteLine($"Устройство с серийным номером 0x{serial:X8} не найдено.");
                        continue;
                    }

                    uint acnt = _lastAcnt != 0 ? _lastAcnt : 0;

                    switch (command)
                    {
                        case "state":
                            // 1. Подписка
                            Console.WriteLine("  -> Отправляем подписку...");
                            byte[] subCmd = TelegramHelper.BuildSubscribeCommand(serial, acnt);
                            await session.SendAsync(subCmd);
                            await Task.Delay(100);

                            // 2. Запрос состояния клиентов
                            Console.WriteLine("  -> Отправляем запрос состояния клиентов...");
                            byte[] clientStateCmd = TelegramHelper.BuildClientStateCommand(serial, acnt);
                            await session.SendAsync(clientStateCmd);
                            await Task.Delay(100);

                            // 3. Запрос состояния устройства
                            Console.WriteLine("  -> Отправляем запрос состояния устройства...");
                            byte[] stateCmd = TelegramHelper.BuildDeviceStateCommand(serial, acnt);
                            await session.SendAsync(stateCmd);
                            Console.WriteLine($"Запрос состояния отправлен устройству 0x{serial:X8}");
                            break;

                        case "subscribe":
                            byte[] subCmdManual = TelegramHelper.BuildSubscribeCommand(serial, acnt);
                            Console.WriteLine($"  Отправка подписки: {BitConverter.ToString(subCmdManual)}");
                            await session.SendAsync(subCmdManual);
                            Console.WriteLine($"Подписка отправлена устройству 0x{serial:X8}");
                            break;

                        case "logon":
                            uint sysNumber = 0;
                            if (parts.Length >= 3)
                            {
                                string sysStr = parts[2];
                                if (sysStr.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                                    sysNumber = Convert.ToUInt32(sysStr.Substring(2), 16);
                                else
                                    sysNumber = Convert.ToUInt32(sysStr);
                            }
                            byte[] logonCmd = TelegramHelper.BuildLogOnCommand(serial, sysNumber);
                            Console.WriteLine($"  Отправка LogOn с sysNumber=0x{sysNumber:X8}: {BitConverter.ToString(logonCmd)}");
                            await session.SendAsync(logonCmd);
                            Console.WriteLine($"LogOn отправлен устройству 0x{serial:X8}");
                            break;

                        case "readheader":
                            byte[] headerCmd = TelegramHelper.BuildReadCommand(serial, 0xFE, 1, acnt);
                            Console.WriteLine($"  Отправка: {BitConverter.ToString(headerCmd)}");
                            await session.SendAsync(headerCmd);
                            Console.WriteLine($"Команда чтения заголовка отправлена (acnt=0x{acnt:X8})");
                            break;

                        case "readkey":
                            if (parts.Length < 3)
                            {
                                Console.WriteLine("Укажите адрес (индекс) ключа.");
                                break;
                            }
                            uint readAddr = Convert.ToUInt32(parts[2]);
                            byte[] readCmd = TelegramHelper.BuildReadCommand(serial, 0x0F, readAddr, acnt);
                            Console.WriteLine($"  Отправка: {BitConverter.ToString(readCmd)}");
                            await session.SendAsync(readCmd);
                            Console.WriteLine($"Команда чтения ключа отправлена (адрес {readAddr})");
                            break;

                        case "unknown":
                            byte[] unknownCmd = TelegramHelper.BuildInquiryCommand(serial, 0x0F, 0xF3, acnt, new byte[4] { 0, 0, 0, 0 });
                            Console.WriteLine($"  Отправка: {BitConverter.ToString(unknownCmd)}");
                            await session.SendAsync(unknownCmd);
                            Console.WriteLine($"Запрос неизвестных ключей отправлен устройству 0x{serial:X8}");
                            break;

                        case "clientstate":
                            byte[] clientStateCmdManual = TelegramHelper.BuildClientStateCommand(serial, acnt);
                            Console.WriteLine($"  Отправка: {BitConverter.ToString(clientStateCmdManual)}");
                            await session.SendAsync(clientStateCmdManual);
                            Console.WriteLine($"Запрос состояния клиентов отправлен устройству 0x{serial:X8}");
                            break;

                        default:
                            Console.WriteLine($"Неизвестная команда: {command}");
                            break;
                    }
                }
            }
        }
    }
}