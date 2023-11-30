// @ts-check
// Note: type annotations allow type checking and IDEs autocompletion

const lightCodeTheme = require('prism-react-renderer/themes/github')
const darkCodeTheme = require('prism-react-renderer/themes/dracula')

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'Ark',
  tagline: 'TBD',
  favicon: 'img/ark-logo.png',
  url: 'https://dev.arkpill.me',
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
          routeBasePath: "/",
          sidebarPath: require.resolve('./sidebars.js'),
          // Please change this to your repo.
          // Remove this to remove the "edit this page" links.
          editUrl: 'https://github.com/ark-network/edit/master/website/',
        },
        blog: {
          showReadingTime: true,
          // Please change this to your repo.
          // Remove this to remove the "edit this page" links.
          editUrl: 'https://github.com/ark-network/edit/master/website/blog/',
        },
      }),
    ],
  ],

  themeConfig:
    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    ({
      // Replace with your project's social card
      image: 'img/ark-og-image.png',
      navbar: {
        title: 'Developer Portal',
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
            title: 'DOCS',
            items: [
              {
                label: 'What Ark is',
                to: '/specs/index',
              },
              {
                label: 'Join the Ark',
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
                label: 'Stack Exchange',
                href: 'https://bitcoin.stackexchange.com/questions/tagged/ark',
              },
              {
                label: 'Github',
                href: 'https://github.com/ark-network',
              }
            ],
          },
          {
            title: 'MORE',
            items: [
              {
                label: 'Blog',
                to: '/blog',
              }
            ],
          },
        ],
        copyright: `Copyright © ${new Date().getFullYear()} Ark. Built with Docusaurus.`,
      },
      colorMode: {
        defaultMode: 'dark',
      },
      prism: {
        theme: lightCodeTheme,
        darkTheme: darkCodeTheme,
      },
    }),
}

module.exports = config
