using System;

namespace KeyGuardServer
{
    public class SessionClosedEventArgs : EventArgs
    {
        public Guid SessionId { get; }
        public bool Removed { get; }

        public SessionClosedEventArgs(Guid sessionId, bool removed)
        {
            SessionId = sessionId;
            Removed = removed;
        }
    }
}