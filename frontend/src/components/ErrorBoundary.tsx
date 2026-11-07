import { Component, type ReactNode } from "react";

/** Shows what went wrong instead of a blank page. */
export class ErrorBoundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state = { error: null as Error | null };

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  render() {
    if (!this.state.error) return this.props.children;
    return (
      <div className="mx-auto max-w-xl px-6 py-16">
        <h1 className="display text-2xl">ThreatLens couldn't show this page</h1>
        <p className="mt-3 text-muted">
          Check that the ThreatLens backend is running on port 8001 (see the README), then reload. If another project's backend is running, stop it first.
        </p>
        <pre className="log mt-5 whitespace-pre-wrap rounded-lg border border-line bg-panel p-3 text-faint">{this.state.error.message}</pre>
        <button className="btn btn-primary mt-5" onClick={() => window.location.reload()}>Reload</button>
      </div>
    );
  }
}
