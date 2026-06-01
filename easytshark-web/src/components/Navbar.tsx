import React, { useEffect, useRef, useState } from 'react';
import { useHistory } from 'react-router-dom';
import { Button, Message, Popover } from '@arco-design/web-react';
import { IconFile, IconHome, IconPlayCircle, IconRecordStop, IconSave } from '@arco-design/web-react/icon';
import Capture from './Capture.tsx';
import { apiGet, apiPost, apiUploadFile } from '../Api.ts';

import "../style/global.css"

const STATUS_IDLE = 0
const STATUS_ANALYSIS_FILE = 1
const STATUS_CAPTURING = 2
const STATUS_MONITORING = 3

function Navbar({ onUpdateData = null }) {
  const [stopLoading, setStopLoading] = useState(false)
  const [workStatus, setWorkStatus] = useState(STATUS_IDLE)
  const [poperVisible, setPoperVisible] = useState(false)
  const [fileLoading, setFileLoading] = useState(false)
  const fileInputRef = useRef(null)

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
    Message.info('停止抓包!');
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

  const handleSelectFile = async () => {
    try {
      if (!(window as any).electronAPI?.openFileDialog) {
        fileInputRef.current?.click()
        return
      }

      const selectedFilePath = await (window as any).electronAPI.openFileDialog()
      if (selectedFilePath) {
        setFileLoading(true)
        try {
          await apiPost('/api/analysisFile', { filePath: selectedFilePath })
          if (onUpdateData != null) onUpdateData()
        } catch (error) {
          Message.error('文件分析失败')
          console.error('analysis file failed', error)
        } finally {
          setFileLoading(false)
        }
      }
    } catch (error) {
      console.error('file select failed', error);
    }
  };

  const handleUploadFile = async (event) => {
    const file = event.target.files?.[0]
    event.target.value = ''
    if (!file) return

    setFileLoading(true)
    try {
      await apiUploadFile('/api/uploadAnalysisFile', file)
      if (onUpdateData != null) onUpdateData()
    } catch (error) {
      Message.error('文件分析失败')
      console.error('upload analysis file failed', error)
    } finally {
      setFileLoading(false)
    }
  }

  const saveFile = async () => {
    try {
      if (!(window as any).electronAPI?.showSavePath) {
        Message.warning('浏览器模式暂不支持保存到指定路径，请使用 Electron 客户端')
        return
      }

      const selectedFilePath = await (window as any).electronAPI.showSavePath()
      if (selectedFilePath) {
        try {
          await apiPost('/api/savePacket', { savePath: selectedFilePath, filter: '' })
          Message.success('保存成功')
        } catch {
        }
      }
    } catch (error) {
      console.error('save file failed', error);
    }
  }

  useEffect(() => {
    checkStatus()
  }, [])

  return (
    <div id="nav-bar" style={{ padding: 10 }}>
      <input
        ref={fileInputRef}
        type="file"
        accept=".pcap,.cap,.pcapng"
        style={{ display: 'none' }}
        onChange={handleUploadFile}
      />
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
      <Button type="primary" onClick={handleSelectFile} loading={fileLoading} icon={<IconFile />} disabled={workStatus !== STATUS_IDLE}>分析文件</Button>
      <Button type="primary" onClick={saveFile} icon={<IconSave />}>保存文件</Button>
    </div>
  );
}

export default Navbar;
