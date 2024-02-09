// @ts-check
// Note: type annotations allow type checking and IDEs autocompletion

const lightCodeTheme = require('prism-react-renderer/themes/synthwave84')
const darkCodeTheme = require('prism-react-renderer/themes/dracula')

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'Ark',
  tagline: 'TBD',
  favicon: 'img/ark-logo.png',
  url: 'https://arkdev.info',
  baseUrl: '/',
  organizationName: 'Ark',
  projectName: 'Ark Website',
  onBrokenLinks: 'throw',
  onBrokenMarkdownLinks: 'warn',
  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  presets: [
    [
      'classic',
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        docs: {
          routeBasePath: '/',
          sidebarPath: require.resolve('./sidebars.js'),
          editUrl: 'https://github.com/ark-network/ark/edit/master/website/',
          exclude: [
            '**/provider/gateway/**',
            '**/provider/coordinator/**', 
            '**/provider/treasury/**',
            '**/user/ark-cli.md'
          ]
        },
        blog: {
          showReadingTime: true,
          editUrl:
            'https://github.com/ark-network/ark/edit/master/website/blog',

          blogTitle: 'Blog',
          blogDescription: 'Posts about Ark development',
        },
      }),
    ],
  ],

  themeConfig:
    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    ({
      // Replace with your project's social card
      image: 'img/ark-banner.png',
      navbar: {
        title: 'Ark',
        logo: {
          alt: 'Ark Logo',
          src: 'img/ark-logo.png',
          srcDark: 'img/ark-logo.png',
        },
        items: [
          {
            type: 'docSidebar',
            sidebarId: 'tutorialSidebar',
            position: 'left',
            label: 'Docs',
          },
          { to: '/blog', label: 'Blog', position: 'left' },
          {
            href: 'https://github.com/ark-network',
            label: 'GitHub',
            position: 'right',
          },
        ],
      },
      footer: {
        links: [
          {
            title: 'LEARN',
            items: [
              {
                label: 'Nomenclature',
                to: '/learn/nomenclature',
              },
              {
                label: 'Board an Ark',
                to: '/learn/boarding',
              },
              {
                label: 'Send Payments',
                to: '/learn/payments',
              },
              {
                label: 'Leave an Ark',
                to: '/learn/leaving',
              },
            ],
          },
          {
            title: 'DOCS',
            items: [
              {
                label: 'Overview',
                to: '/',
              },
              {
                label: 'Join an Ark',
                to: '/user/intro',
              },
              {
                label: 'Create an Ark',
                to: '/provider/intro',
              },
            ],
          },
          {
            title: 'COMMUNITY',
            items: [
              {
                label: 'Telegram',
                href: 'https://t.me/ark_network_community',
              },
              {
                label: 'Stack Exchange',
                href: 'https://bitcoin.stackexchange.com/questions/tagged/ark',
              },
              {
                label: 'Github',
                href: 'https://github.com/ark-network',
              },
            ],
          },
          {
            title: 'MORE',
            items: [
              {
                label: 'Blog',
                to: '/blog',
              },
            ],
          },
        ],
      },
      colorMode: {
        defaultMode: 'light',
        disableSwitch: false,
        respectPrefersColorScheme: true,
      },
      prism: {
        theme: lightCodeTheme,
        darkTheme: darkCodeTheme,
      },
    }),
  markdown: {
    mermaid: true,
  },
  themes: ['@docusaurus/theme-mermaid'],
}

module.exports = config
