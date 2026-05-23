import React, { useState } from 'react';
import { Navigate } from 'react-router-dom';

export default function LoginPage() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [remember, setRemember] = useState(true);

  const [submitting, setSubmitting] = useState(false);

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    try {
      // Submit to Flask so session cookie is created.
      const form = document.createElement('form');
      form.method = 'POST';
      form.action = '/login';

      const u = document.createElement('input');
      u.name = 'username';
      u.value = username;
      form.appendChild(u);

      const p = document.createElement('input');
      p.name = 'password';
      p.value = password;
      form.appendChild(p);

      const r = document.createElement('input');
      r.name = 'remember';
      r.value = remember ? 'on' : '';
      r.type = 'checkbox';
      if (remember) r.checked = true;
      form.appendChild(r);

      document.body.appendChild(form);
      form.submit();
    } finally {
      setSubmitting(false);
    }
  };

  // If user is already logged in, Flask would normally redirect at /.
  return (
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 20 }}>
      <div
        style={{
          background: 'rgba(255,255,255,0.95)',
          backdropFilter: 'blur(10px)',
          padding: 40,
          borderRadius: 20,
          boxShadow: '0 15px 35px rgba(0,0,0,0.1)',
          width: '100%',
          maxWidth: 420,
          border: '1px solid rgba(255,255,255,0.2)',
        }}
      >
        <div style={{ textAlign: 'center', marginBottom: 30 }}>
          <h1 style={{ color: '#1e293b', fontSize: 32, fontWeight: 700, marginBottom: 10, background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
            <i className="fas fa-shield-alt" /> Hybrid IDS
          </h1>
          <p style={{ color: '#64748b', fontSize: 16 }}>Sign in to your account</p>
        </div>

        <form onSubmit={onSubmit}>
          <div style={{ marginBottom: 20 }}>
            <label style={{ display: 'block', marginBottom: 8, color: '#374151', fontWeight: 500, fontSize: 14 }}>Username</label>
            <input value={username} onChange={(e) => setUsername(e.target.value)} type="text" required style={inputStyle} />
          </div>

          <div style={{ marginBottom: 20 }}>
            <label style={{ display: 'block', marginBottom: 8, color: '#374151', fontWeight: 500, fontSize: 14 }}>Password</label>
            <input value={password} onChange={(e) => setPassword(e.target.value)} type="password" required style={inputStyle} />
          </div>

          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 25 }}>
            <label style={{ color: '#64748b', display: 'flex', alignItems: 'center', gap: 8, fontSize: 14 }}>
              <input type="checkbox" checked={remember} onChange={(e) => setRemember(e.target.checked)} /> Remember me
            </label>
            <a href="#" style={{ color: '#667eea', textDecoration: 'none', fontSize: 14 }}>
              Forgot password?
            </a>
          </div>

          <button type="submit" disabled={submitting} style={btnStyle}>
            <i className="fas fa-sign-in-alt" /> {submitting ? 'Signing in...' : 'Sign In'}
          </button>

          <div style={{ textAlign: 'center', marginTop: 16, color: '#64748b', fontSize: 14 }}>
            Don't have an account? <a href="/register" style={{ color: '#667eea', fontWeight: 500 }}>Create one here</a>
          </div>
        </form>
      </div>
    </div>
  );
}

const inputStyle: React.CSSProperties = {
  width: '100%',
  padding: '12px 16px',
  border: '2px solid #e5e7eb',
  borderRadius: 10,
  fontSize: 16,
  transition: 'all 0.3s ease',
  background: 'rgba(255,255,255,0.8)',
};

const btnStyle: React.CSSProperties = {
  width: '100%',
  padding: 14,
  background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
  color: 'white',
  border: 'none',
  borderRadius: 10,
  fontSize: 16,
  fontWeight: 600,
  cursor: 'pointer',
};

