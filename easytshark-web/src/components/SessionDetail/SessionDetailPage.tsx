import React, { useEffect } from 'react';
import { Tabs, Radio, Typography } from '@arco-design/web-react';
import "../../style/global.css"
import SessionTimeGraphTab from './SessionTimeGraphTab.tsx';
import SessionDataStreamhTab from './SessionDataStreamTab.tsx';
import { useLocation } from 'react-router-dom';

const TabPane = Tabs.TabPane;

function SessionDetailPage() {

    const location = useLocation();
    const params = new URLSearchParams(location.search);
    const windowParams = new URLSearchParams(window.location.search)
    const sessionId = params.get('sessionId') || windowParams.get('sessionId')

    return (
        <Tabs type='card'>
            <TabPane key='1' title='会话时序图'>
                <SessionTimeGraphTab sessionId={sessionId}></SessionTimeGraphTab>
            </TabPane>
            <TabPane key='2' title='会话数据流'>
                <SessionDataStreamhTab sessionId={sessionId}></SessionDataStreamhTab>
            </TabPane>
        </Tabs>
    );
}

export default SessionDetailPage;