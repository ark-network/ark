import React, { useEffect, useState } from 'react'

const isArm = async () => {
  // available on Chrome, Edge and Opera
  if (typeof navigator.userAgentData?.getHighEntropyValues === 'function') {
    const { architecture } = await navigator.userAgentData.getHighEntropyValues(
      ['architecture']
    )
    return architecture === 'arm'
  }
  // for Firefox
  const w = document.createElement('canvas').getContext('webgl')
  const d = w.getExtension('WEBGL_debug_renderer_info')
  const g = (d && w.getParameter(d.UNMASKED_RENDERER_WEBGL)) || ''
  return Boolean(g.match(/Apple M[123]/)) // TODO: Linux
}

const Button = ({ children, onClick, colored }) => {
  const backgroundColor = colored
    ? 'var(--ifm-color-primary-lightest)'
    : 'var(--ifm-color-emphasis-200)'
  return (
    <button
      onClick={onClick}
      style={{
        backgroundColor,
        borderRadius: '8px',
        borderWidth: '1px',
        cursor: 'pointer',
        fontSize: '1rem',
        padding: '1rem',
        width: '18rem',
      }}>
      {children}
    </button>
  )
}

const Section = ({ children }) => (
  <div style={{ margin: '10vh 0', maxWidth: '600px' }}>{children}</div>
)

const SpaceBetween = ({ children }) => (
  <div
    style={{
      display: 'flex',
      justifyContent: 'space-between',
    }}>
    {children}
  </div>
)

export default function Buttons() {
  const [binaryUrl, setBinaryUrl] = useState('')
  const [downloadText, setDownloadText] = useState('Download binary')

  const fileURL = (filename) =>
    `https://install-latest-cli.arkdev.info/latest-release/${filename}`

  useEffect(async () => {
    const nua = navigator.userAgent
    const isMacOS = Boolean(nua.match(/OS X /))
    const isLinux = Boolean(nua.match(/Linux/))
    const isSafari = Boolean(nua.includes('Safari') && !nua.includes('Chrome'))
    if (!isMacOS && !isLinux) return // no binaries available
    if (isSafari) return // Safari hides the CPU architecture
    const os = isMacOS ? 'darwin' : 'linux'
    const arch = (await isArm()) ? 'arm64' : 'amd64'
    const file = `ark-${os}-${arch}`
    setBinaryUrl(fileURL(file))
    setDownloadText(`Download ${file}`)
  })

  const viewOnGithub = () =>
    window.open('https://github.com/ark-network/ark', '_blank')

  const downloadAlpha = () => {
    // if we know user OS and architecture, start download immediately
    if (!binaryUrl) window.open(binaryUrl, '_blank')
    document.querySelector('#available-binaries').scrollIntoView({
      behavior: 'smooth',
    })
  }

  return (
    <Section>
      <SpaceBetween>
        <Button onClick={viewOnGithub}>
          <SpaceBetween>
            View on Github
            <svg
              className='github_svg__lucide github_svg__lucide-github'
              xmlns='http://www.w3.org/2000/svg'
              width='1em'
              height='1em'
              fill='none'
              stroke='currentColor'
              strokeLinecap='round'
              strokeLinejoin='round'
              strokeWidth='2'
              viewBox='0 0 24 24'>
              <path d='M15 22v-4a4.8 4.8 0 0 0-1-3.5c3 0 6-2 6-5.5.08-1.25-.27-2.48-1-3.5.28-1.15.28-2.35 0-3.5 0 0-1 0-3 1.5-2.64-.5-5.36-.5-8 0C6 2 5 2 5 2c-.3 1.15-.3 2.35 0 3.5A5.4 5.4 0 0 0 4 9c0 3.5 3 5.5 6 5.5-.39.49-.68 1.05-.85 1.65S8.93 17.38 9 18v4'></path>
              <path d='M9 18c-4.51 2-5-2-7-2'></path>
            </svg>
          </SpaceBetween>
        </Button>
        <Button onClick={downloadAlpha} colored={true}>
          <SpaceBetween>
            {downloadText}
            <svg
              className='download_svg__lucide download_svg__lucide-download'
              xmlns='http://www.w3.org/2000/svg'
              width='1em'
              height='1em'
              fill='none'
              stroke='currentColor'
              strokeLinecap='round'
              strokeLinejoin='round'
              strokeWidth='2'
              viewBox='0 0 24 24'>
              <path d='M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3'></path>
            </svg>
          </SpaceBetween>
        </Button>
      </SpaceBetween>
    </Section>
  )
}
