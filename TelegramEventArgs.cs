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
    // ------------------- Аргументы события с телеграммой -------------------
    public class TelegramEventArgs : EventArgs
    {
        public byte[] Telegram { get; }
        public EndPoint RemoteEndPoint { get; }
        public ClientSession Session { get; }

        public TelegramEventArgs(byte[] telegram, EndPoint remoteEndPoint, ClientSession session)
        {
            Telegram = telegram;
            RemoteEndPoint = remoteEndPoint;
            Session = session;
        }
    }
}