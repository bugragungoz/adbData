import { render } from 'preact';
import './styles/tokens.css';
import './styles/fonts.css';
import './styles/base.css';
import './styles/components.css';
import './styles/layout.css';
import { App } from './App';

render(<App />, document.getElementById('app')!);
