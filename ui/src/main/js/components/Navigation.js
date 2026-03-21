import React from 'react';
import { Link } from 'react-router-dom';
import { useTheme } from 'context/ThemeContext';

export default function Navigation({ fluid }) {
  const { theme, toggleTheme } = useTheme();
  return (
    <nav className='navbar'>
      <div className={fluid ? 'container-fluid' : 'container'}>
        <div className='navbar-header'>
          <Link className='navbar-brand' to='/scheduler'>
            <img alt='Brand' src='/assets/images/aurora_logo_white.png' />
          </Link>
        </div>
        <ul className='nav navbar-nav navbar-right'>
          <li><Link to='/updates'>updates</Link></li>
          <li>
            <button className='theme-toggle' onClick={toggleTheme} title='Toggle theme'>
              {theme === 'dark' ? 'Light' : 'Dark'}
            </button>
          </li>
        </ul>
      </div>
    </nav>
  );
}
