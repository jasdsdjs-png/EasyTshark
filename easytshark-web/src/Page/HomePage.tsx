import React, { useRef, useState } from 'react';
import { Message, Spin, Typography } from '@arco-design/web-react';
import { useHistory } from 'react-router-dom';
import { apiGet, apiPost, apiUploadFile } from '../Api.ts';
import { IconPlus } from '@arco-design/web-react/icon';
import Capture from '../components/Capture.tsx';

const HomePage = () => {
  const history = useHistory();
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const [loading, setLoading] = useState(false);
  const [cap, setCap] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [analysisTip, setAnalysisTip] = useState('');

  const onsubmit = () => {
    setCap(true);
    setLoading(true);
    history.push('/data/dataPacket/all');
  };

  const waitForAnalysisTask = async (taskId) => {
    if (!taskId) {
      throw new Error('missing task id');
    }

    while (true) {
      const statusResult = await apiGet(`/api/analysisTasks/${taskId}`);
      const task = statusResult.data;
      setAnalysisTip(`分析任务 ${task.progress || 0}%`);

      if (task.status === 'DONE') {
        await apiPost(`/api/analysisTasks/${taskId}/activate`);
        return;
      }

      if (task.status === 'FAILED' || task.status === 'CANCELED') {
        throw new Error(task.message || 'analysis task failed');
      }

      await new Promise((resolve) => setTimeout(resolve, 800));
    }
  };

  const analysisSelectedFile = async (file) => {
    if (!file) return;

    setCap(false);
    setLoading(true);
    setAnalysisTip('提交分析任务...');
    try {
      await apiGet('/api/stopMonitorAdaptersFlowTrend');
      const result = await apiUploadFile('/api/analysisTasks', file);
      await waitForAnalysisTask(result.data.taskId);
      history.push('/data/dataPacket/all');
    } catch (error) {
      Message.error('文件分析失败');
      console.error('upload analysis file failed', error);
    } finally {
      setLoading(false);
      setAnalysisTip('');
    }
  };

  const handleSelectFile = () => {
    fileInputRef.current?.click();
  };

  const handleFileInputChange = (event) => {
    const file = event.target.files?.[0];
    event.target.value = '';
    analysisSelectedFile(file);
  };

  const handleDropFile = (event) => {
    event.preventDefault();
    setDragging(false);
    analysisSelectedFile(event.dataTransfer.files?.[0]);
  };

  return <div>
    <Spin loading={loading} style={{ width: '100%' }} tip={analysisTip || `${cap ? '实时抓包' : '文件'}分析中...`}>
      <div className='home' style={{ padding: '30px 20%' }}>
        <Typography.Title heading={6}>实时抓包分析</Typography.Title>
        <Capture onsubmit={onsubmit} />
        <Typography.Title heading={6}>离线分析文件</Typography.Title>
        <input
          ref={fileInputRef}
          type="file"
          accept=".pcap,.cap,.pcapng"
          style={{ display: 'none' }}
          onChange={handleFileInputChange}
        />
        <div
          className={`input-file ${dragging ? 'dragging' : ''}`}
          onClick={handleSelectFile}
          onDragOver={(event) => {
            event.preventDefault();
            setDragging(true);
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={handleDropFile}
          style={{ height: 80 }}
        >
          <p><IconPlus style={{ fontSize: 22 }} /></p>
          <p>点击或拖拽文件到此处上传</p>
        </div>
      </div>
    </Spin>
  </div>;
};

export default HomePage;
