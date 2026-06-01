import React from 'react';
import PageLayout from './Page/PageLayout.tsx';
import SessionDetailPage from './components/SessionDetail/SessionDetailPage.tsx';
import { HashRouter, Redirect, Route, Switch } from 'react-router-dom';
import HomePage from './Page/HomePage.tsx';

function App() {

  return (
    <HashRouter>
      <div className="App">
        <Switch>
          <Redirect exact from="/" to="/home" />
          <Route path="/home" component={HomePage} />
          <Route path="/data" component={PageLayout} />
          <Route path="/detail" component={SessionDetailPage} />
        </Switch>
      </div>
    </HashRouter>
    
  );
}

export default App;
