import React, { useState, useEffect, useRef } from 'react';
import './styles/SessionDetailStyle.css'
//import '../../style/global.css'
import { Card, Grid, Spin, Tabs, Tag, Typography } from '@arco-design/web-react';
import { calculateDuration } from '../../util.ts'
import { apiFetchData } from '../../Api.ts';
import { useLocation } from 'react-router-dom';
import DataPacketPage from "../DataPacketPage.tsx";

const { Ellipsis } = Typography


function SessionTimeGraphTab(props) {

    const [data, setData] = useState([])
    const [currentRowId, setCurrentRowId] = useState([1])
    const location = useLocation();
    const params = new URLSearchParams(location.search);
    const windowParams = new URLSearchParams(window.location.search)
  
    const sessionId = params.get('sessionId') || windowParams.get('sessionId')
    console.log("sessionId", sessionId)
    const [record, setRecord] = useState(JSON.parse(localStorage.getItem(`row${sessionId}`)))
  
    const loadTimeGraph = async () => {
        const _data = await apiFetchData('/api/getPacketList', {
            pageSize: 100,
            pageNum: 1,
            session_id: parseInt(sessionId)
        });
    
        setData(_data.data);
    }

    const DataPacketPageRef = useRef(null);

    
    useEffect(() => {
        loadTimeGraph()
    }, [])
    

    return (
        <div style={{ margin: 20 }} className='details'>
            <div style={{ margin: '0 10px 10px 10px' }}>
                <Grid.Row gutter={24} style={{ flexFlow: 'nowrap' }}>
                    <Typography.Paragraph style={{ minWidth: 450 }}>
                    <Grid.Col span={7} className='details-col'>
                        <div className='first-col flex items-center'>
                            <div style={{ width: 165 }}>
                                <div><Typography.Ellipsis showTooltip className='text-[14px]'>{record.ip1}:{record.ip1_port}</Typography.Ellipsis></div>
                                <Ellipsis showTooltip className='mt-2'><span>{record.ip1_location}</span></Ellipsis>
                            </div>
                            <div style={{ textAlign: 'center', padding: '0 15px 0 5px' }}>
                                <div className='arrow'>
                                    <span className="proto">
                                        <Tag bordered color='arcoblue' size='small'>{record.app_proto || record.trans_proto}</Tag>
                                    </span>
                                    <span className="icon"></span>
                                </div>
                                <span>{calculateDuration(record.start_time, record.end_time)}</span>
                            </div>
                            <div style={{ width: 165 }}>
                                <div><Typography.Ellipsis showTooltip className='text-[14px]'>{record.ip2}:{record.ip2_port}</Typography.Ellipsis></div>
                                <Ellipsis className='mt-2'><span>{record.ip2_location}</span></Ellipsis>
                            </div>
                        </div>

                        
                        {data.map((item, index) => {
                            const split = item.timestamp.toString().split('.')
                            return <div key={item.frame_number} id={`box-${item.frame_number}`}
                                        className={`box ${((currentRowId === item.frame_number) || (!currentRowId && index === 0)) ? 'selected' : null} flex items-center cursor-pointer`}
                                        onClick={() => { 
                                            setCurrentRowId(item.frame_number)
                                            DataPacketPageRef.current.setCurrentRowId(item.frame_number)
                                         }}
                                        >
                                        <div className='flex' style={{ width: 165 }}>
                                            <div style={{ width: 60 }}>{item.frame_number}</div>
                                            {index === 0 ? 0 : ((item.timestamp * 1000000) - (data[0].timestamp * 1000000)) / 1000000}
                                        </div>
                                        <div style={{ margin: '0 15px 0 10px' }}>
                                            <div className={`arrow ${item.src_ip === record.ip1 ? 'arrow-right' : 'arrow-left'}`}
                                                style={{ marginTop: '-10px' }}
                                            >
                                                <span className="icon"></span>
                                            </div>
                                        </div>
                                        <div style={{ width: 165 }}>
                                            <div className='flex items-center'>
                                                <div style={{ width: 40 }}>{item.len}</div>
                                                <Typography.Ellipsis showTooltip style={{ width: 130 }}>{item.info}</Typography.Ellipsis>
                                            </div>
                                        </div>
                                   </div>
                        })}
                    </Grid.Col>
                    </Typography.Paragraph>
                    <Grid.Col span={17} style={{ marginTop: -10, flexGrow: 1 }}>
                        <DataPacketPage
                            ref={DataPacketPageRef}
                            match={{
                                params: {
                                    type: 'detail',
                                    sessionId: sessionId
                                  },
                            }}
                        >
                        </DataPacketPage>
                    </Grid.Col>
                </Grid.Row>
                </div>
            </div>
    )
    
}


export default SessionTimeGraphTab