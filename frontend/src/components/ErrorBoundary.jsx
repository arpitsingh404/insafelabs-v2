import { Component } from "react";

// Catches render errors anywhere below so a single bad component can't blank the
// whole console (see frontend audit: e.g. an unexpected API shape). Fails visibly
// with a reload affordance instead of a white screen.
export class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { error: null };
  }

  static getDerivedStateFromError(error) {
    return { error };
  }

  componentDidCatch(error, info) {
    // eslint-disable-next-line no-console
    console.error("[InsafeLabs] UI error:", error, info?.componentStack);
  }

  render() {
    if (this.state.error) {
      return (
        <div className="min-h-screen flex flex-col items-center justify-center gap-4 bg-background text-zinc-300 p-6" data-testid="app-error-boundary">
          <div className="w-10 h-10 border border-severity-critical/50 flex items-center justify-center text-severity-critical font-mono">!</div>
          <h1 className="font-heading text-xl">Something went wrong rendering this view.</h1>
          <p className="font-mono text-xs text-zinc-500 max-w-lg text-center break-all">{String(this.state.error?.message || this.state.error)}</p>
          <div className="flex gap-2">
            <button onClick={() => this.setState({ error: null })}
              className="border border-border px-4 py-2 font-mono text-xs uppercase tracking-wider text-zinc-300 hover:text-primary hover:border-primary/50 transition-colors">
              Try again
            </button>
            <button onClick={() => window.location.assign("/app")}
              className="bg-primary text-black px-4 py-2 font-mono text-xs uppercase tracking-wider hover:bg-yellow-500 transition-colors">
              Reload console
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}
