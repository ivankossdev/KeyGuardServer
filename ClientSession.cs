using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace KeyGuardServer
{
    public class ClientSession : IDisposable
    {
        private readonly TcpClient _client;
        private readonly NetworkStream _stream;
        private readonly KeyGuardTcpServer _server;
        private readonly byte[] _readBuffer = new byte[4096];
        private readonly List<byte> _accumulator = new List<byte>();
        private readonly Guid _id = Guid.NewGuid();
        private bool _disposed = false;

        public Guid Id => _id;

        private static readonly byte[] StartMarker = { 0xA5, 0x5A, 0xB6, 0x6B };
        private static readonly byte[] EndMarker = { 0xB8, 0x8B, 0xC9, 0x9C };

        public ClientSession(TcpClient client, KeyGuardTcpServer server)
        {
            _client = client ?? throw new ArgumentNullException(nameof(client));
            _server = server ?? throw new ArgumentNullException(nameof(server));
            _stream = client.GetStream() ?? throw new InvalidOperationException("Unable to get network stream");
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] Клиент подключён: {client.Client?.RemoteEndPoint} (Id: {_id})");
        }

        public async Task ProcessAsync(CancellationToken cancellationToken)
        {
            try
            {
                while (!cancellationToken.IsCancellationRequested && _client.Connected)
                {
                    int bytesRead = await _stream.ReadAsync(_readBuffer, 0, _readBuffer.Length, cancellationToken);
                    if (bytesRead == 0)
                        break;

                    lock (_accumulator)
                    {
                        _accumulator.AddRange(_readBuffer.AsSpan(0, bytesRead).ToArray());
                        ProcessBuffer();
                    }
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] Ошибка в сессии {Id}: {ex.Message}");
            }
            finally
            {
                Dispose();
            }
        }

        private void ProcessBuffer()
        {
            while (true)
            {
                int startIndex = FindSequence(_accumulator, StartMarker);
                if (startIndex == -1)
                {
                    _accumulator.Clear();
                    return;
                }

                if (startIndex > 0)
                    _accumulator.RemoveRange(0, startIndex);

                if (_accumulator.Count < 16 + 2)
                    return;

                int len = _accumulator[16] | (_accumulator[17] << 8);
                int totalPacketSize = 4 + len + 4;

                if (_accumulator.Count < totalPacketSize)
                    return;

                if (!CheckSequence(_accumulator, totalPacketSize - 4, EndMarker))
                {
                    _accumulator.RemoveRange(0, 4);
                    continue;
                }

                byte[] telegram = _accumulator.GetRange(0, totalPacketSize).ToArray();
                _accumulator.RemoveRange(0, totalPacketSize);

                var remoteEndPoint = _client.Client?.RemoteEndPoint ?? new IPEndPoint(IPAddress.Any, 0);
                _server.OnTelegramReceived(telegram, remoteEndPoint, this);
            }
        }

        private int FindSequence(List<byte> source, byte[] pattern)
        {
            for (int i = 0; i <= source.Count - pattern.Length; i++)
            {
                bool found = true;
                for (int j = 0; j < pattern.Length; j++)
                {
                    if (source[i + j] != pattern[j])
                    {
                        found = false;
                        break;
                    }
                }
                if (found) return i;
            }
            return -1;
        }

        private bool CheckSequence(List<byte> source, int startIndex, byte[] pattern)
        {
            if (startIndex + pattern.Length > source.Count) return false;
            for (int i = 0; i < pattern.Length; i++)
                if (source[startIndex + i] != pattern[i]) return false;
            return true;
        }

        public async Task SendAsync(byte[] telegram)
        {
            if (telegram == null)
                throw new ArgumentNullException(nameof(telegram));

            if (_disposed || !_client.Connected)
            {
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] Попытка отправки в закрытую сессию {Id}");
                return;
            }

            try
            {
                await _stream.WriteAsync(telegram, 0, telegram.Length);
                await _stream.FlushAsync();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] Ошибка отправки в сессии {Id}: {ex.Message}");
                Dispose();
            }
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;

            try
            {
                _client?.Close();
                _stream?.Dispose();
            }
            catch { }

            _server.OnSessionClosed(this);
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] Клиент {Id} отключён.");
        }
    }
}