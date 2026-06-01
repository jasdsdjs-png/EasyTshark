import React, { useEffect, useRef, useState } from 'react';
import { Empty, Radio, Spin } from '@arco-design/web-react';
import { hexCharCodeToAscStr, strSexteenSplit, strTwoSplit, isInteger, padNumber, formatFileSize } from '../../util.ts'
import { apiPost } from '../../Api.ts';
const RadioGroup = Radio.Group;


function SessionDataStreamhTab({ sessionId }) {
  const leftRef = useRef(null)
  const [data, setData] = useState([])
  const [countObj, setCountObj] = useState(null)
  const [loading, setLoading] = useState(false)
  const pageNum = 1
  const [type, setType] = useState('ascii')
  const record = JSON.parse(localStorage.getItem(`row${sessionId}`))

  // 获取数据流
  const getSessionDataStream = async (value?: any) => {
    setLoading(true)
    const values: any = await apiPost('/api/getSessionDataStream', { session_id: record.session_id ?? record.session_id })
    setCountObj(values?.count)
    const datas = value === 'b' ? values?.data.filter(v => v.srcNode === values?.count?.node0) :
      value === 'c' ? values?.data.filter(v => v.srcNode === values?.count?.node1) : values?.data

    datas.map(item => {
      if (item.hexData !== '') {
        const arr = getAscTransformation(item.hexData)
        item.offsetData = arr.offsetData
        item.ascData = arr.ascData
        item.hexData = arr.hexData
        item.hexAscData = arr.hexAscData
      }
    })
    if (pageNum === 1) {
      setData(datas)
    } else {
      setData([...data, ...datas])
    }
    setLoading(false)
  }
  // 组装十六进制展示
  const getAscTransformation = (hex) => {
    let hexData = []
    const ascData = []
    let hexAscData = []
    const offsetData = []
    // 按16位分割ascii
    const ascParams = hexCharCodeToAscStr(hex)
    ascData.push(ascParams)
    hexAscData = strSexteenSplit(ascParams, 16, '换').split('换')
    // 按16位分割hex
    const arr = strTwoSplit(hex).split(',')
    hexData = strSexteenSplit(arr, 16, ',').split(',')

    // 计算偏移量 不够四位左侧补位0
    for (let i = 0; i < hexAscData.length; i++) {
      const offset = padNumber((i * 16).toString(16), 8, 0)
      offsetData.push(offset)
    }
    return { hexData, ascData, offsetData, hexAscData }
  }
  useEffect(() => {
    getSessionDataStream()
    return () => {
      localStorage.removeItem('row')
    };
  }, [])
  return (
    <div>
        <RadioGroup defaultValue='a' style={{ marginBottom: 10 }} onChange={(value) => getSessionDataStream(value)}>
            <Radio value='a'>全部（{formatFileSize(countObj?.node0BytesCount + countObj?.node1BytesCount)}，{countObj?.totalPacketCount}个数据包）</Radio>
            <Radio value='b'><span style={{ color: '#C04545' }}>{countObj?.node0}</span> -&gt; <span style={{ color: '#319EFF' }}>{countObj?.node1}</span> ({formatFileSize(countObj?.node0BytesCount)}，{countObj?.node0PacketCount}个数据包)</Radio>
            <Radio value='c'><span style={{ color: '#319EFF' }}>{countObj?.node1}</span> -&gt; <span style={{ color: '#C04545' }}>{countObj?.node0}</span>（{formatFileSize(countObj?.node1BytesCount)}，{countObj?.node1PacketCount}个数据包）</Radio>
        </RadioGroup>
        <div>
            <RadioGroup value={type} style={{ marginBottom: 10 }} type='button' onChange={(value => { setType(value); })}>
                <Radio value='ascii'>ASCII</Radio>
                <Radio value='rawData'>原始数据</Radio>
                <Radio value='hex'>HEX转储</Radio>
            </RadioGroup>
        </div>
        <Spin loading={loading} block>
            {data.length === 0 ? <Empty className='mt-5' /> :
                type === 'ascii' &&
                <div className='stream-main' ref={leftRef}>
                {data.map((item, i) => <div key={i} className={item.srcNode == countObj?.node0 ? 'send' : 'accept'}>
                    {item.ascData.map((info, j) =>
                    <pre key={j} style={{ marginBottom: 0, whiteSpace: 'break-spaces', fontFamily: 'Consolas, monospace' }}>{info}</pre>
                    )}
                </div>)}
                </div>}
            {type === 'rawData' && <div className='stream-main'>
                {data.map((item, index) => <div key={index} className={item.srcNode == countObj?.node0 ? 'send' : 'accept'}>
                {item.hexData}
                </div>)}
            </div>}
            {type === 'hex' && <div className='stream-main'>
                {data.map((item, index) => <div className={`${item.srcNode == countObj?.node0 ? 'send' : 'accept'} stream-offset mgb20`} key={index}>
                <div className="left">
                    {item.offsetData.map((v) => <div key={v}>{v}</div>)}
                </div>
                <div className="center">
                    {item.hexData.map((v) => <div key={v}>{v}</div>)}
                </div>
                <div className="right">
                    {item.hexAscData.map((v) => <div key={v}>{v}</div>)}

                </div>
                </div>)}

            </div>}
        </Spin>
    </div>
    )
}

export default SessionDataStreamhTab;
