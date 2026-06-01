import React, { useEffect, useRef, useState } from 'react';
import { Button, Card, Grid, Message, Typography } from '@arco-design/web-react';
import styles from '../style/home.css'
import LineChart from './LineChart.tsx';
import { apiGet, apiPost } from '../Api.ts';

function Capture({ type = '', onsubmit = null }) {
    const [datas, setDatas] = useState([])
    const [loading, setLoading] = useState(false)
    const intervalIdRef = useRef(null)
    const hasShownNetworkErrorRef = useRef(false)

    const showBackendWarning = () => {
        if (!hasShownNetworkErrorRef.current) {
            Message.warning('后端服务未连接，无法获取网卡流量数据')
            hasShownNetworkErrorRef.current = true
        }
    }

    const startMonitorAdaptersFlowTrend = async () => {
        try {
            await apiGet('/api/startMonitorAdaptersFlowTrend')
            getAdaptersFlowTrendData()
        } catch (error) {
            setDatas([])
            showBackendWarning()
        }
    }

    const getAdaptersFlowTrendData = async () => {
        try {
            const values = await apiGet('/api/getAdaptersFlowTrendData')
            setDatas(values?.data || [])
            hasShownNetworkErrorRef.current = false
        } catch (error) {
            setDatas([])
            showBackendWarning()
        }
    }

    const startCapture = async (key) => {
        try {
            setLoading(true)
            await apiPost('/api/startCapture', { adapterName: key })
            onsubmit(type)
        } catch (error) {
            Message.error('启动抓包失败，请确认后端服务已启动')
        } finally {
            setLoading(false)
        }
    }

    const stopMonitorAdaptersFlowTrend = async (item?: any, type?: string) => {
        try {
            await apiGet('/api/stopMonitorAdaptersFlowTrend')
        } catch (error) {
            // Backend may be offline in browser-only development mode.
        }
        if (type) {
            startCapture(item)
        }
    }

    useEffect(() => {
        startMonitorAdaptersFlowTrend()
        intervalIdRef.current = setInterval(getAdaptersFlowTrendData, 1000)
        return () => {
            if (intervalIdRef.current !== null) {
                clearInterval(intervalIdRef.current)
                intervalIdRef.current = null
            }
            stopMonitorAdaptersFlowTrend()
        };
    }, [])

    return <Card style={{
                background: 'var(--color-fill-1)',
                maxHeight: 250,
                overflowY: 'auto',
                overflowX: 'hidden',
            }}
            className='mb-[20px]'>
            {Object.entries(datas).map(([key, value]) => (
                <div className={`${styles['lines']} mb-[10px]`} key={key}>
                    <Grid.Row gutter={24} style={{ alignItems: 'end' }}>
                        <Grid.Col span={5}><Typography.Ellipsis showTooltip>{key}</Typography.Ellipsis></Grid.Col>
                        <Grid.Col span={16}><LineChart data={value} /></Grid.Col>
                        <Grid.Col span={3} style={{ textAlign: 'right' }}><Button type='primary' loading={loading} size={type ? 'small' : 'default'} onClick={() => stopMonitorAdaptersFlowTrend(key, 'cap')}>抓包</Button></Grid.Col>
                    </Grid.Row>
                </div>
            ))}
        </Card>;
}

export default Capture;
