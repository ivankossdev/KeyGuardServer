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

                if (header.Src != 0 && (header.Src & 0xF0000000) != 0xF0000000)
                {
                    _sessions[header.Src] = e.Session;
                    Console.WriteLine($"  -> Сессия для устройства 0x{header.Src:X8} обновлена");
                }

                Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] Получена телеграмма от {e.RemoteEndPoint}:");
                Console.WriteLine($"  Cmd=0x{header.Cmd:X2}, Ident=0x{header.Ident:X2}, Value=0x{header.Value:X2}, Ref={header.Ref}, Src=0x{header.Src:X8}, Dst=0x{header.Dst:X8}");
                
                // ---- Детальный разбор по типам событий (Cmd=0x80) ----
                if (header.Cmd == 0x80)
                {
                    // 1. Карта приложена / доступ разрешён
                    if (header.Ident == 0x03 && (header.Value == 0x80 || header.Value == 0x83))
                    {
                        string eventName = (header.Value == 0x80) ? "Карта приложена" : "Доступ разрешён";
                        if (payload.Length >= 4)
                        {
                            uint readerAddr = BitConverter.ToUInt32(payload, 0);
                            string cardHex = "";
                            if (payload.Length >= 12) // addr (4) + card[8]
                            {
                                byte[] card = new byte[8];
                                Array.Copy(payload, 4, card, 0, Math.Min(8, payload.Length - 4));
                                cardHex = BitConverter.ToString(card);
                            }
                            // Acnt: если старший байт != 0, то это номер карты, иначе номер пользователя
                            uint acnt = header.Acnt;
                            string acntInfo = "";
                            if ((acnt & 0xFF000000) != 0)
                                acntInfo = $" (карта #{acnt >> 24}, пользователь #{acnt & 0x00FFFFFF})";
                            else
                                acntInfo = $" (пользователь #{acnt})";
                            Console.WriteLine($"  -> {eventName}: считыватель {readerAddr}, карта {cardHex}{acntInfo}");
                        }
                        else
                        {
                            Console.WriteLine($"  -> {eventName}: недостаточно данных");
                        }
                    }
                    // 2. Ключ выдан / возвращён
                    else if (header.Ident == 0x0F && (header.Value == 0x32 || header.Value == 0x72))
                    {
                        string eventName = (header.Value == 0x32) ? "Ключ выдан" : "Ключ возвращён";
                        if (payload.Length >= 6)
                        {
                            uint keyAddr = BitConverter.ToUInt32(payload, 0);
                            byte module = payload[4];
                            byte cell = payload[5];
                            // Acnt
                            uint acnt = header.Acnt;
                            string acntInfo = "";
                            if ((acnt & 0xFF000000) != 0)
                                acntInfo = $" (карта #{acnt >> 24}, пользователь #{acnt & 0x00FFFFFF})";
                            else
                                acntInfo = $" (пользователь #{acnt})";
                            Console.WriteLine($"  -> {eventName}: ключ #{keyAddr}, модуль {module}, ячейка {cell}{acntInfo}");
                        }
                        else
                        {
                            Console.WriteLine($"  -> {eventName}: недостаточно данных");
                        }
                    }
                    // 3. Дверь открыта / закрыта
                    else if (header.Ident == 0x08 && (header.Value == 0x10 || header.Value == 0x50))
                    {
                        string state = (header.Value == 0x10) ? "открыта" : "закрыта";
                        if (payload.Length >= 4)
                        {
                            uint detAddr = BitConverter.ToUInt32(payload, 0);
                            Console.WriteLine($"  -> Дверь {state}: датчик {detAddr}");
                        }
                        else
                        {
                            Console.WriteLine($"  -> Дверь {state}: недостаточно данных");
                        }
                    }
                    // 4. Прочие события (логируем как есть)
                    else
                    {
                        Console.WriteLine($"  -> Событие Ident=0x{header.Ident:X2}, Value=0x{header.Value:X2}, Payload: {BitConverter.ToString(payload)}");
                    }
                }
                // ---- Ответы на запросы (Cmd=0x83/0x85) ----
                else if (header.Cmd == 0x83 || header.Cmd == 0x85)
                {
                    // Ответ на запрос состояния устройства (Cmd=0xF3 мы уже обрабатывали)
                    // Здесь можно добавить другие ответы, если появятся
                    Console.WriteLine($"  <- Ответ (Cmd=0x{header.Cmd:X2}): Ident=0x{header.Ident:X2}, Value=0x{header.Value:X2}");
                }
                // ---- Подтверждение записи (Cmd=0x90) ----
                else if (header.Cmd == 0x90)
                {
                    if (header.Value == 0xE1)
                    {
                        Console.WriteLine($"  <- Подтверждение записи (Ident=0x{header.Ident:X2})");
                        if (payload.Length >= 4)
                        {
                            uint addr = BitConverter.ToUInt32(payload, 0);
                            Console.WriteLine($"    Запись выполнена для элемента с адресом {addr}");
                        }
                    }
                    else if (header.Value == 0xE2)
                    {
                        // Ответ на чтение — мы уже обрабатываем ниже
                        // но можно оставить для общности
                    }
                    else
                    {
                        Console.WriteLine($"  <- Команда БД: Value=0x{header.Value:X2}, Payload: {BitConverter.ToString(payload)}");
                    }
                }
                // ---- WatchDog ----
                else if (header.Cmd == 0xA2 && header.Ident == 0xE5 && header.Value == 0x31)
                {
                    Console.WriteLine("  -> Отвечаем на WatchDog");
                    byte[] ack = TelegramHelper.BuildWatchDogResponse(header.Src, header.Ref, _lastAcnt);
                    await e.Session.SendAsync(ack);
                }
                // ---- LogOn ответ ----
                else if (header.Cmd == 0xA0 && header.Ident == 0xE0 && header.Value == 0xF1)
                    Console.WriteLine("  <- LogOn подтверждён устройством");
                else if (header.Cmd == 0xA6 && header.Ident == 0xE0 && header.Value == 0xF1)
                    Console.WriteLine("  <- LogOn отклонён (NAC)");

                // ---- Старые обработчики (для чтения и прочего) оставляем в конце ----
                // (они уже были, их можно оставить как есть)
                // ... 
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
            Console.WriteLine("  fullstate <serial>       - отправить полный запрос состояния клиентов (payload 234)");
            Console.WriteLine("  statetest <serial>      - отправить полную последовательность (пустая+полная 0x65 + state)");
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
                        case "statetest":
                            // Аналогично state, но можно отдельно
                            // Используем ту же логику, что и в state
                            goto case "state"; // или скопировать код

                        case "state":
                            // 1. Подписка
                            Console.WriteLine("  -> Отправляем подписку...");
                            byte[] subCmd = TelegramHelper.BuildSubscribeCommand(serial, acnt);
                            await session.SendAsync(subCmd);
                            await Task.Delay(100);

                            // 2. Пустая 0x65
                            Console.WriteLine("  -> Отправляем пустую команду 0x65...");
                            byte[] emptyCmd = TelegramHelper.BuildClientStateEmptyCommand(serial, acnt);
                            await session.SendAsync(emptyCmd);
                            await Task.Delay(100);

                            // 3. Полная 0x65
                            Console.WriteLine("  -> Отправляем полную команду 0x65...");
                            byte[] fullCmd = TelegramHelper.BuildClientStateFullCommand(serial, acnt);
                            await session.SendAsync(fullCmd);
                            await Task.Delay(100);

                            // 4. Запрос состояния устройства
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

                        case "fullstate":
                            byte[] fullStateCmd = TelegramHelper.BuildClientStateFullCommand(serial, acnt);
                            Console.WriteLine($"  Отправка fullstate: {BitConverter.ToString(fullStateCmd)}");
                            await session.SendAsync(fullStateCmd);
                            Console.WriteLine($"Полный запрос состояния клиентов отправлен устройству 0x{serial:X8}");
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