interface PoCFrameProps {
  src: string;
  title: string;
}

export function PoCFrame({ src, title }: PoCFrameProps) {
  return (
    <iframe
      src={src}
      title={title}
      style={{ border: 0, display: 'block', height: '100vh', width: '100vw' }}
    />
  );
}
