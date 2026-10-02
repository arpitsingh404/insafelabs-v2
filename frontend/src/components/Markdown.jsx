import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

export function Markdown({ children, className = "" }) {
  return (
    <div className={`text-[13px] leading-relaxed text-zinc-200 break-words ${className}`}>
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        components={{
          h1: (p) => <h1 className="text-base font-bold text-white mt-3 mb-1.5" {...p} />,
          h2: (p) => <h2 className="text-sm font-bold text-white mt-3 mb-1.5" {...p} />,
          h3: (p) => <h3 className="text-sm font-semibold text-primary mt-2.5 mb-1" {...p} />,
          p: (p) => <p className="my-1.5" {...p} />,
          strong: (p) => <strong className="font-bold text-white" {...p} />,
          em: (p) => <em className="italic text-zinc-300" {...p} />,
          ul: (p) => <ul className="list-disc pl-5 my-1.5 space-y-1" {...p} />,
          ol: (p) => <ol className="list-decimal pl-5 my-1.5 space-y-1" {...p} />,
          li: (p) => <li className="marker:text-primary/70" {...p} />,
          a: (p) => <a className="text-primary underline underline-offset-2 hover:text-yellow-400" target="_blank" rel="noreferrer" {...p} />,
          blockquote: (p) => <blockquote className="border-l-2 border-primary/40 pl-3 my-2 text-zinc-400" {...p} />,
          hr: () => <hr className="my-3 border-border" />,
          table: (p) => <div className="overflow-x-auto my-2"><table className="w-full text-xs border border-border" {...p} /></div>,
          th: (p) => <th className="border border-border bg-white/5 px-2 py-1 text-left font-semibold" {...p} />,
          td: (p) => <td className="border border-border px-2 py-1" {...p} />,
          pre: ({ children }) => <>{children}</>,
          code: ({ className: cn, children }) => {
            const isBlock = /language-/.test(cn || "") || String(children).includes("\n");
            return isBlock ? (
              <pre className="block bg-[#0a0a0a] border border-border p-3 my-2 overflow-x-auto">
                <code className="text-[12px] font-mono text-zinc-300 whitespace-pre">{children}</code>
              </pre>
            ) : (
              <code className="bg-black/50 border border-border px-1 py-0.5 text-[12px] font-mono text-primary">{children}</code>
            );
          },
        }}
      >
        {children || ""}
      </ReactMarkdown>
    </div>
  );
}
