using System;
using System.Net;

namespace KeyGuardTcpServer
{
    public class TelegramEventArgs : EventArgs
    {
        public byte[] Telegram { get; }
        public EndPoint RemoteEndPoint { get; }
        public ClientSession Session { get; }

        public TelegramEventArgs(byte[] telegram, EndPoint remoteEndPoint, ClientSession session)
        {
            Telegram = telegram ?? throw new ArgumentNullException(nameof(telegram));
            RemoteEndPoint = remoteEndPoint ?? throw new ArgumentNullException(nameof(remoteEndPoint));
            Session = session ?? throw new ArgumentNullException(nameof(session));
        }
    }
}