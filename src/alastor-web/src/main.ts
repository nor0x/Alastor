import { mount } from 'svelte';
import '@fontsource/familjen-grotesk/latin-500.css';
import '@fontsource/familjen-grotesk/latin-600.css';
import '@fontsource/ibm-plex-sans/latin-400.css';
import '@fontsource/ibm-plex-sans/latin-500.css';
import '@fontsource/jetbrains-mono/latin-400.css';
import './app.css';
import App from './App.svelte';

mount(App, { target: document.getElementById('app')! });
