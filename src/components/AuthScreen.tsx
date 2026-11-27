import React, { useEffect, useState } from 'react';
import { Eye, EyeOff, Languages, Lock, Moon, ShieldCheck, Sun } from 'lucide-react';
import { ApiError, fetchConfig, fetchSupabaseSchema, login, signup } from '../api/client';
import { getTranslator } from '../i18n/translations';
import type { AppConfig, Language, ThemeId, UserSession } from '../types/logbook';

interface AuthScreenProps {
  theme: ThemeId;
  lang: Language;
  onChangeTheme: (theme: ThemeId) => void;
  onChangeLang: (lang: Language) => void;
  onAuthenticated: (user: UserSession) => void;
}

export const AuthScreen: React.FC<AuthScreenProps> = ({
  theme,
  lang,
  onChangeTheme,
  onChangeLang,
  onAuthenticated,
}) => {
  const t = getTranslator(lang);
  const [mode, setMode] = useState<'login' | 'signup'>('login');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [config, setConfig] = useState<AppConfig | null>(null);

  const [submitting, setSubmitting] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');
  const [schemaMissing, setSchemaMissing] = useState(false);
  const [copiedSql, setCopiedSql] = useState(false);

  useEffect(() => {
    fetchConfig()
      .then(setConfig)
      .catch(() => {});
  }, []);

  const handleCopySql = async () => {
    try {
      const res = await fetchSupabaseSchema();
      await navigator.clipboard.writeText(res.sql);
      setCopiedSql(true);
      setTimeout(() => setCopiedSql(false), 2000);
    } catch {
      // ignore
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg('');
    setSchemaMissing(false);

    const trimmedUsername = username.trim().toLowerCase();
    if (!trimmedUsername || !password) {
      setErrorMsg(t('authMissingFields'));
      return;
    }

    if (mode === 'signup') {
      if (!/^[a-z0-9][a-z0-9._-]{1,63}$/.test(trimmedUsername)) {
        setErrorMsg(t('usernameInvalid'));
        return;
      }
      if (password.length < 12) {
        setErrorMsg(t('passwordMinLength'));
        return;
      }
    }

    if (password.length > 128) {
      setErrorMsg(t('passwordMaxLength'));
      return;
    }

    const activeConfig = config || (await fetchConfig().catch(() => null));
    if (!activeConfig?.supabaseConfigured) {
      setErrorMsg(t('supabaseNotConfigured'));
      return;
    }

    setSubmitting(true);
    try {
      const res =
        mode === 'signup'
          ? await signup({ username: trimmedUsername, password })
          : await login({ username: trimmedUsername, password });
      onAuthenticated(res.user);
    } catch (err) {
      if (err instanceof ApiError && err.code === 'SCHEMA_MISSING') {
        setSchemaMissing(true);
      }
      setErrorMsg(err instanceof Error ? err.message : 'Authentication failed');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen flex flex-col justify-between bg-[var(--bg-canvas)] text-[var(--text-primary)] px-4 py-6">
      <header className="w-full max-w-5xl mx-auto flex items-center justify-between gap-4">
        <div className="flex items-center gap-2.5">
          <span className="text-lg font-semibold tracking-tight">{t('appName')}</span>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => onChangeLang(lang === 'en' ? 'fa' : 'en')}
            aria-label="Toggle language"
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg border border-[var(--border-hairline)] bg-[var(--bg-surface)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:border-[var(--border-strong)] transition-colors whitespace-nowrap"
          >
            <Languages className="w-3.5 h-3.5" />
            <span>{lang === 'en' ? 'فارسی' : 'English'}</span>
          </button>

          <button
            type="button"
            onClick={() => onChangeTheme(theme === 'light' ? 'dark' : 'light')}
            aria-label="Toggle color theme"
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg border border-[var(--border-hairline)] bg-[var(--bg-surface)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:border-[var(--border-strong)] transition-colors whitespace-nowrap"
          >
            {theme === 'light' ? <Moon className="w-3.5 h-3.5" /> : <Sun className="w-3.5 h-3.5" />}
            <span>{theme === 'light' ? t('themeDark') : t('themeLight')}</span>
          </button>
        </div>
      </header>

      <main className="w-full max-w-[420px] mx-auto my-8">
        <div className="rounded-xl border border-[var(--border-hairline)] bg-[var(--bg-surface)] p-7">
          <div className="mb-6">
            <h1 className="text-xl font-semibold tracking-tight text-[var(--text-primary)]">
              {mode === 'login' ? t('signInTitle') : t('signUpTitle')}
            </h1>
            <p className="mt-1.5 text-sm text-[var(--text-secondary)]">
              {mode === 'login' ? t('signInSubtitle') : t('signUpSubtitle')}
            </p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label htmlFor="auth-username" className="block text-xs font-medium text-[var(--text-secondary)] mb-1.5">
                {t('username')}
              </label>
              <input
                id="auth-username"
                type="text"
                dir="ltr"
                autoComplete="username"
                maxLength={64}
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder={t('usernamePlaceholder')}
                className="w-full px-3.5 py-2.5 text-sm rounded-lg bg-[var(--bg-canvas)] border border-[var(--border-hairline)] text-[var(--text-primary)] placeholder:text-[var(--text-muted)] focus:outline-none focus:border-[var(--accent)]"
                required
              />
            </div>

            <div>
              <label htmlFor="auth-password" className="block text-xs font-medium text-[var(--text-secondary)] mb-1.5">
                {t('password')}
              </label>
              <div className="relative">
                <input
                  id="auth-password"
                  type={showPassword ? 'text' : 'password'}
                  dir={password ? 'ltr' : lang === 'fa' ? 'rtl' : 'ltr'}
                  autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
                  minLength={mode === 'signup' ? 12 : undefined}
                  maxLength={128}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder={mode === 'signup' ? t('passwordPlaceholder') : '••••••••••••'}
                  className="w-full px-3.5 py-2.5 pe-10 text-sm rounded-lg bg-[var(--bg-canvas)] border border-[var(--border-hairline)] text-[var(--text-primary)] placeholder:text-[var(--text-muted)] focus:outline-none focus:border-[var(--accent)]"
                  required
                />
                <button
                  type="button"
                  onClick={() => setShowPassword((v) => !v)}
                  aria-label={showPassword ? t('hidePassword') : t('showPassword')}
                  className="absolute end-2.5 top-1/2 -translate-y-1/2 p-1 text-[var(--text-muted)] hover:text-[var(--text-primary)]"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {errorMsg && (
              <div
                role="alert"
                className="px-3.5 py-2.5 rounded-lg text-xs font-medium bg-red-500/10 border border-red-500/30 text-red-400 space-y-2"
              >
                <div>{errorMsg}</div>
                {schemaMissing && (
                  <button
                    type="button"
                    onClick={handleCopySql}
                    className="inline-block px-2.5 py-1 rounded bg-[var(--bg-surface)] border border-[var(--border-strong)] text-[var(--text-primary)] hover:bg-[var(--bg-hover)]"
                  >
                    {copiedSql ? t('copied') : t('copySqlSchema')}
                  </button>
                )}
              </div>
            )}

            <button
              type="submit"
              disabled={submitting}
              className="w-full py-2.5 px-4 rounded-lg text-sm font-medium text-white bg-[var(--accent)] hover:bg-[var(--accent-hover)] disabled:opacity-50 transition-colors flex items-center justify-center gap-2"
            >
              <Lock className="w-4 h-4" />
              <span>{submitting ? t('pleaseWait') : mode === 'login' ? t('signIn') : t('createAccount')}</span>
            </button>
          </form>

          <div className="mt-5 text-center text-sm text-[var(--text-secondary)]">
            {mode === 'login' ? (
              <>
                {t('noAccountYet')}{' '}
                <button
                  type="button"
                  onClick={() => {
                    setMode('signup');
                    setErrorMsg('');
                    setSchemaMissing(false);
                  }}
                  className="font-medium text-[var(--accent)] hover:underline"
                >
                  {t('createOne')}
                </button>
              </>
            ) : (
              <>
                {t('alreadyRegistered')}{' '}
                <button
                  type="button"
                  onClick={() => {
                    setMode('login');
                    setErrorMsg('');
                    setSchemaMissing(false);
                  }}
                  className="font-medium text-[var(--accent)] hover:underline"
                >
                  {t('signIn')}
                </button>
              </>
            )}
          </div>
        </div>
      </main>

      <footer className="w-full max-w-5xl mx-auto flex items-center justify-center gap-2 text-xs text-[var(--text-muted)]">
        <ShieldCheck className="w-3.5 h-3.5 shrink-0" />
        <span>{t('authFooter')}</span>
      </footer>
    </div>
  );
};
