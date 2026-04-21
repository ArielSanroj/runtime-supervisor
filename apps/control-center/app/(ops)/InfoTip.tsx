export default function InfoTip({ children }: { children: React.ReactNode }) {
  return (
    <span className="info-tip" tabIndex={0} role="button" aria-label="info">
      ?
      <span className="tip">{children}</span>
    </span>
  );
}
