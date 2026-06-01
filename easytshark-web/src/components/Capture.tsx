import React, { useEffect, useState } from 'react';
import { Button, Card, Grid, Typography } from '@arco-design/web-react';
import styles from '../style/home.css'
import LineChart from './LineChart.tsx';
import { apiGet, apiPost } from '../Api.ts';

function Capture({ type = '', onsubmit = null }) {
    const [datas, setDatas] = useState([])
    const [loading, setLoading] = useState(false)
    let intervalId = null
    // 监控网卡流量趋势
    const startMonitorAdaptersFlowTrend = async () => {
        await apiGet('/api/startMonitorAdaptersFlowTrend')
        getAdaptersFlowTrendData()
    }
    // 获取流量趋势数据
    const getAdaptersFlowTrendData = async () => {
        const values = await apiGet('/api/getAdaptersFlowTrendData')
        setDatas(values?.data || [])
    }
    // 开始抓包
    const startCapture = async (key) => {
        setLoading(true)
        await apiPost('/api/startCapture', { adapterName: key })
        onsubmit(type)
        setLoading(false)
    }
    // 停止监控网卡流量趋势
    const stopMonitorAdaptersFlowTrend = async (item?: any, type?: string) => {
        await apiGet('/api/stopMonitorAdaptersFlowTrend')
        if (type)
            startCapture(item)
    }
    useEffect(() => {
        startMonitorAdaptersFlowTrend()
        intervalId = setInterval(getAdaptersFlowTrendData, 1000);
        return () => {
            if (intervalId !== null) {
                clearInterval(intervalId);
                stopMonitorAdaptersFlowTrend();
            }
        };
    }, [])
    return <Card style={{
                background: 'var(--color-fill-1)',
                maxHeight: 250,
                overflowY: 'auto',   // 当内容超出时，显示垂直滚动条
                overflowX: 'hidden', // 隐藏水平滚动条
            }}
            className='mb-[20px]'>
            {Object.entries(datas).map(([key, value]) => (
                <div className={`${styles['lines']} mb-[10px]`} key={key}>
                    <Grid.Row gutter={24} style={{ alignItems: 'end' }}>
                        <Grid.Col span={5}><Typography.Ellipsis showTooltip>{key}</Typography.Ellipsis></Grid.Col>
                        <Grid.Col span={16}><LineChart data={value} /></Grid.Col>
                        <Grid.Col span={3} style={{ textAlign: 'right' }}><Button type='primary' size={type ? 'small' : 'default'} onClick={() => stopMonitorAdaptersFlowTrend(key, 'cap')}>抓包</Button></Grid.Col>
                    </Grid.Row>
                </div>
            ))}
        </Card>;
}

export default Capture;
