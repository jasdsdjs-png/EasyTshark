import React, { useEffect, useState } from 'react';
import { useHistory } from 'react-router-dom';
import { Button, Message, Popover } from '@arco-design/web-react';
import { IconHome, IconPlayCircle, IconRecordStop } from '@arco-design/web-react/icon';
import Capture from './Capture.tsx';
import { apiGet } from '../Api.ts';

import "../style/global.css"

const STATUS_IDLE = 0
const STATUS_ANALYSIS_FILE = 1
const STATUS_CAPTURING = 2
const STATUS_MONITORING = 3

function Navbar({ onUpdateData = null }) {
  const [stopLoading, setStopLoading] = useState(false)
  const [workStatus, setWorkStatus] = useState(STATUS_IDLE)
  const [poperVisible, setPoperVisible] = useState(false)

  const history = useHistory();

  const goHome = () => {
    history.push("/home")
  }

  const checkStatus = async () => {
    const _data = await apiGet('/api/getWorkStatus');
    setWorkStatus(_data.data.workStatus)
  }

  const stopCapture = async () => {
    setStopLoading(true)
    await apiGet('/api/stopCapture')
    Message.info('已停止抓包');
    setStopLoading(false)
    checkStatus()
  };

  const onCaptureSubmit= () => {
    setPoperVisible(false);
    if (onUpdateData != null) {
      checkStatus()
      onUpdateData()
    }
  }

  useEffect(() => {
    checkStatus()
  }, [])

  return (
    <div id="nav-bar" style={{ padding: 10 }}>
      <Button type="primary" onClick={goHome} status='warning' icon={<IconHome />} disabled={workStatus !== STATUS_IDLE}>首页</Button>

      <Popover
        title='实时抓包分析'
        trigger="click"
        popupVisible={poperVisible}
        className='!max-w-[650px]'
        onVisibleChange={(value) => setPoperVisible(value)}
        content={<div className='w-[600px]'><Capture type="home" onsubmit={onCaptureSubmit} /></div>}
      >
        <Button
          type="primary"
          icon={<IconPlayCircle /> }
          disabled={[STATUS_ANALYSIS_FILE, STATUS_CAPTURING].includes(workStatus)}
          >
          开始抓包
        </Button>
      </Popover>

      <Button type="primary" status="danger" onClick={stopCapture} loading={stopLoading} icon={<IconRecordStop />} disabled={[STATUS_IDLE, STATUS_ANALYSIS_FILE, STATUS_MONITORING].includes(workStatus)}>停止抓包</Button>
    </div>
  );
}

export default Navbar;
