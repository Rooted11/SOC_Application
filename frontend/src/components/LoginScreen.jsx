import { useState } from "react";

export default function LoginScreen({ busy, error, mfaEnabled, onSubmit }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [otpCode, setOtpCode] = useState("");

  async function handleSubmit(event) {
    event.preventDefault();
    await onSubmit({ username, password, otpCode });
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <div className="fixed inset-0 -z-10 bg-[radial-gradient(circle_at_top,_rgba(14,165,233,0.16),_transparent_28%),radial-gradient(circle_at_80%_20%,_rgba(249,115,22,0.12),_transparent_22%),linear-gradient(180deg,_#020617_0%,_#020617_55%,_#08111f_100%)]" />

      <div className="mx-auto flex min-h-screen max-w-6xl items-center px-6 py-12">
        <div className="grid w-full gap-8 lg:grid-cols-[1.2fr_minmax(360px,420px)]">
          <section className="rounded-[32px] border border-cyan-500/10 bg-slate-950/60 p-8 shadow-[0_30px_120px_rgba(2,6,23,0.65)] backdrop-blur">
            <div className="text-[11px] uppercase tracking-[0.35em] text-cyan-400">
              Ataraxia SOC
            </div>
            <h1 className="mt-4 max-w-3xl text-4xl font-semibold tracking-tight text-white sm:text-5xl">
              Public operator access now requires authentication.
            </h1>
            <p className="mt-5 max-w-2xl text-base leading-7 text-slate-400">
              The console is configured for internet-facing use, with protected API
              routes, tighter origin controls, and production-safe deployment defaults.
            </p>

            <div className="mt-10 grid gap-4 sm:grid-cols-3">
              <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-4">
                <div className="text-xs uppercase tracking-[0.25em] text-slate-500">
                  Access
                </div>
                <div className="mt-3 text-sm text-slate-300">
                  Bearer-token auth for all protected API routes.
                </div>
              </div>
              <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-4">
                <div className="text-xs uppercase tracking-[0.25em] text-slate-500">
                  Origins
                </div>
                <div className="mt-3 text-sm text-slate-300">
                  Restricted hosts and production CORS defaults.
                </div>
              </div>
              <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-4">
                <div className="text-xs uppercase tracking-[0.25em] text-slate-500">
                  Runtime
                </div>
                <div className="mt-3 text-sm text-slate-300">
                  Production images avoid dev servers and hot reload.
                </div>
              </div>
            </div>
          </section>

          <section className="rounded-[28px] border border-slate-800 bg-slate-950/80 p-8 shadow-[0_30px_80px_rgba(2,6,23,0.55)] backdrop-blur">
            <div className="text-sm uppercase tracking-[0.3em] text-slate-500">
              Operator Sign In
            </div>
            <h2 className="mt-3 text-2xl font-semibold text-white">
              Ataraxia access
            </h2>
            <p className="mt-2 text-sm leading-6 text-slate-400">
              Use the credentials configured on the backend via environment variables.
              {mfaEnabled ? " This environment also requires a one-time code." : ""}
            </p>

            <form className="mt-8 space-y-5" onSubmit={handleSubmit}>
              <label className="block">
                <span className="mb-2 block text-xs uppercase tracking-[0.25em] text-slate-500">
                  Username
                </span>
                <input
                  type="text"
                  autoComplete="username"
                  value={username}
                  onChange={(event) => setUsername(event.target.value)}
                  className="w-full rounded-2xl border border-slate-800 bg-slate-900/80 px-4 py-3 text-sm text-white outline-none transition focus:border-cyan-500/50 focus:ring-2 focus:ring-cyan-500/20"
                  placeholder="soc_operator"
                  required
                />
              </label>

              <label className="block">
                <span className="mb-2 block text-xs uppercase tracking-[0.25em] text-slate-500">
                  Password
                </span>
                <input
                  type="password"
                  autoComplete="current-password"
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  className="w-full rounded-2xl border border-slate-800 bg-slate-900/80 px-4 py-3 text-sm text-white outline-none transition focus:border-cyan-500/50 focus:ring-2 focus:ring-cyan-500/20"
                  placeholder="Enter operator password"
                  required
                />
              </label>

              {mfaEnabled && (
                <label className="block">
                  <span className="mb-2 block text-xs uppercase tracking-[0.25em] text-slate-500">
                    One-Time Code
                  </span>
                  <input
                    type="text"
                    inputMode="numeric"
                    autoComplete="one-time-code"
                    value={otpCode}
                    onChange={(event) => setOtpCode(event.target.value.replace(/\D/g, "").slice(0, 6))}
                    className="w-full rounded-2xl border border-slate-800 bg-slate-900/80 px-4 py-3 text-sm tracking-[0.3em] text-white outline-none transition focus:border-cyan-500/50 focus:ring-2 focus:ring-cyan-500/20"
                    placeholder="123456"
                    required
                  />
                </label>
              )}

              {error && (
                <div className="rounded-2xl border border-rose-500/30 bg-rose-500/10 px-4 py-3 text-sm text-rose-200">
                  {error}
                </div>
              )}

              <button
                type="submit"
                disabled={busy}
                className="inline-flex w-full items-center justify-center rounded-2xl bg-cyan-400 px-4 py-3 text-sm font-semibold text-slate-950 transition hover:bg-cyan-300 disabled:cursor-not-allowed disabled:opacity-60"
              >
                {busy ? "Signing in..." : "Sign In"}
              </button>
            </form>
          </section>
        </div>
      </div>
    </div>
  );
}
