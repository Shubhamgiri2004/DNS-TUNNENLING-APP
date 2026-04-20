import React from 'react';
import ReactDOM from 'react-dom/client';
import URLSafetyChecker from './URLSafetyChecker.tsx';
import './style.css';

ReactDOM.createRoot(document.getElementById('app')!).render(
  React.createElement(URLSafetyChecker)
);
