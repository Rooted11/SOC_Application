import { useState } from "react";
import { api } from "../services/api";

export default function ResetPasswordScreen({ token }) {
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [done, setDone] = useState(false);

  async function handleSubmit(event) {
    event.preventDefault();
    setError(null);

    if (newPassword !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }
    if (newPassword.length < 8) {
      setError("Password must be at least 8 characters.");
      return;
    }

    setBusy(true);
    try {
      await api.resetPassword(token, newPassword);
      setDone(true);
    } catch (submitError) {
      setError(submitError.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <div className="fixed inset-0 -z-10 bg-[radial-gradient(circle_at_top,_rgba(14,165,233,0.16),_transparent_28%),radial-gradient(circle_at_80%_20%,_rgba(249,115,22,0.12),_transparent_22%),linear-gradient(180deg,_#020617_0%,_#020617_55%,_#08111f_100%)]" />

      <div className="mx-auto flex min-h-screen max-w-lg items-center px-6 py-12">
        <section className="w-full rounded-[28px] border border-slate-800 bg-slate-950/80 p-8 shadow-[0_30px_80px_rgba(2,6,23,0.55)] backdrop-blur">
          <div className="text-sm uppercase tracking-[0.3em] text-slate-500">
            Ataraxia SOC
          </div>
          <h2 className="mt-3 text-2xl font-semibold text-white">
            Set a new password
          </h2>

          {done ? (
            <>
              <p className="mt-4 text-sm leading-6 text-slate-400">
                Your password has been reset. You can now sign in with your new password.
              </p>
              <a
                href="/"
                className="mt-6 inline-flex w-full items-center justify-center rounded-2xl bg-cyan-400 px-4 py-3 text-sm font-semibold text-slate-950 transition hover:bg-cyan-300"
              >
                Go to sign in
              </a>
            </>
          ) : (
            <form className="mt-8 space-y-5" onSubmit={handleSubmit}>
              <label className="block">
                <span className="mb-2 block text-xs uppercase tracking-[0.25em] text-slate-500">
                  New password
                </span>
                <input
                  type="password"
                  autoComplete="new-password"
                  value={newPassword}
                  onChange={(event) => setNewPassword(event.target.value)}
                  className="w-full rounded-2xl border border-slate-800 bg-slate-900/80 px-4 py-3 text-sm text-white outline-none transition focus:border-cyan-500/50 focus:ring-2 focus:ring-cyan-500/20"
                  placeholder="At least 8 characters"
                  required
                />
              </label>

              <label className="block">
                <span className="mb-2 block text-xs uppercase tracking-[0.25em] text-slate-500">
                  Confirm new password
                </span>
                <input
                  type="password"
                  autoComplete="new-password"
                  value={confirmPassword}
                  onChange={(event) => setConfirmPassword(event.target.value)}
                  className="w-full rounded-2xl border border-slate-800 bg-slate-900/80 px-4 py-3 text-sm text-white outline-none transition focus:border-cyan-500/50 focus:ring-2 focus:ring-cyan-500/20"
                  placeholder="Re-enter new password"
                  required
                />
              </label>

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
                {busy ? "Resetting..." : "Reset password"}
              </button>
            </form>
          )}
        </section>
      </div>
    </div>
  );
}
