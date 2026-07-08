using System;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace KeyGuardTcpServer
{
    public class KeyGuardTcpServer : IDisposable
    {
        private readonly TcpListener _listener;
        private readonly CancellationTokenSource _cts = new CancellationTokenSource();
        private readonly ConcurrentDictionary<Guid, ClientSession> _sessions = new ConcurrentDictionary<Guid, ClientSession>();

        public event EventHandler<TelegramEventArgs> TelegramReceived = delegate { };

        public KeyGuardTcpServer(int port)
        {
            _listener = new TcpListener(IPAddress.Any, port);
        }

        public void Start()
        {
            _listener.Start();
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] KeyGuard TCP-сервер запущен на порту {((IPEndPoint)_listener.LocalEndpoint).Port}");
            Task.Run(AcceptClientsAsync);
        }

        private async Task AcceptClientsAsync()
        {
            while (!_cts.IsCancellationRequested)
            {
                try
                {
                    var tcpClient = await _listener.AcceptTcpClientAsync();
                    var session = new ClientSession(tcpClient, this);
                    _sessions.TryAdd(session.Id, session);
                    _ = session.ProcessAsync(_cts.Token);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] Ошибка принятия клиента: {ex.Message}");
                }
            }
        }

        internal void OnTelegramReceived(byte[] telegram, EndPoint remoteEndPoint, ClientSession session)
        {
            TelegramReceived?.Invoke(this, new TelegramEventArgs(telegram, remoteEndPoint, session));
        }

        public void Dispose()
        {
            _cts.Cancel();
            _listener.Stop();
            foreach (var s in _sessions.Values)
                s.Dispose();
            _sessions.Clear();
        }
    }
}