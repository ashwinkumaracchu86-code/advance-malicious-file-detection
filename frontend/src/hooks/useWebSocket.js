import { useEffect, useRef, useCallback, useState } from 'react';

export function useWebSocket(onMessage) {
  const wsRef = useRef(null);
  const reconnectRef = useRef(null);
  const pingRef = useRef(null);
  const [connected, setConnected] = useState(false);
  const onMessageRef = useRef(onMessage);
  const mountedRef = useRef(true);

  onMessageRef.current = onMessage;

  const cleanup = useCallback(() => {
    if (reconnectRef.current) {
      clearInterval(reconnectRef.current);
      reconnectRef.current = null;
    }
    if (pingRef.current) {
      clearInterval(pingRef.current);
      pingRef.current = null;
    }
    if (wsRef.current) {
      wsRef.current.onclose = null;
      wsRef.current.close();
      wsRef.current = null;
    }
  }, []);

  const connect = useCallback(() => {
    if (!mountedRef.current) return;
    cleanup();

    try {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const host = window.location.host;
      const wsUrl = `${protocol}//${host}/ws`;

      const token = localStorage.getItem('token');
      const url = token ? `${wsUrl}?token=${token}` : wsUrl;

      const ws = new WebSocket(url);
      wsRef.current = ws;

      ws.onopen = () => {
        if (!mountedRef.current) return;
        setConnected(true);
        if (reconnectRef.current) {
          clearInterval(reconnectRef.current);
          reconnectRef.current = null;
        }
        pingRef.current = setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) {
            ws.send('ping');
          }
        }, 25000);
      };

      ws.onmessage = (event) => {
        if (!mountedRef.current) return;
        try {
          const parsed = JSON.parse(event.data);
          if (parsed.type === 'pong') return;
          onMessageRef.current?.(parsed);
        } catch (e) {
          // ignore parse errors
        }
      };

      ws.onclose = () => {
        if (!mountedRef.current) return;
        setConnected(false);
        if (pingRef.current) {
          clearInterval(pingRef.current);
          pingRef.current = null;
        }
        scheduleReconnect();
      };

      ws.onerror = () => {
        ws.close();
      };
    } catch (e) {
      scheduleReconnect();
    }
  }, [cleanup]);

  const scheduleReconnect = useCallback(() => {
    if (!mountedRef.current) return;
    if (!reconnectRef.current) {
      reconnectRef.current = setInterval(() => {
        if (!mountedRef.current) return;
        if (!wsRef.current || wsRef.current.readyState === WebSocket.CLOSED) {
          connect();
        }
      }, 3000);
    }
  }, [connect]);

  useEffect(() => {
    mountedRef.current = true;
    connect();
    return () => {
      mountedRef.current = false;
      cleanup();
    };
  }, [connect, cleanup]);

  const sendMessage = useCallback((msg) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(typeof msg === 'string' ? msg : JSON.stringify(msg));
    }
  }, []);

  return { connected, sendMessage };
}
