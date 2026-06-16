import React, { useEffect, useMemo, useState } from 'react';
import { Pagination, Table, TableColumnProps, Tag } from '@arco-design/web-react';
import dayjs from 'dayjs';
import { apiFetchData } from '../Api.ts';

const formatTime = (value) => {
  if (!value) {
    return '-';
  }
  const split = value.toString().split('.');
  return `${dayjs(value * 1000).format('YYYY-MM-DD HH:mm:ss')}${split[1] ? `.${split[1]}` : ''}`;
};

const renderList = (value) => {
  if (Array.isArray(value)) {
    return value.length ? value.join(', ') : '-';
  }
  return value || '-';
};

const statsConfig = {
  ip: {
    api: '/api/getIPStatsList',
    columns: [
      { title: 'IP', dataIndex: 'ip', width: 150 },
      { title: '归属地', dataIndex: 'location', width: 180 },
      { title: '首次出现', dataIndex: 'earliest_time', width: 210, render: formatTime },
      { title: '最近出现', dataIndex: 'latest_time', width: 210, render: formatTime },
      { title: '端口', dataIndex: 'ports', width: 180, render: renderList },
      { title: '协议', dataIndex: 'proto', width: 180, render: renderList },
      { title: '发送包数', dataIndex: 'total_sent_packets', width: 120 },
      { title: '接收包数', dataIndex: 'total_recv_packets', width: 120 },
      { title: '发送字节', dataIndex: 'total_sent_bytes', width: 120 },
      { title: '接收字节', dataIndex: 'total_recv_bytes', width: 120 },
      { title: 'TCP会话', dataIndex: 'tcp_session_count', width: 100 },
      { title: 'UDP会话', dataIndex: 'udp_session_count', width: 100 },
    ],
  },
  proto: {
    api: '/api/getProtoStatsList',
    columns: [
      {
        title: '协议',
        dataIndex: 'proto',
        width: 140,
        render: (value) => <Tag color="arcoblue">{value || '-'}</Tag>,
      },
      { title: '协议说明', dataIndex: 'proto_description', width: 360 },
      { title: '数据包数', dataIndex: 'total_packets', width: 140 },
      { title: '总字节数', dataIndex: 'total_bytes', width: 140 },
      { title: '会话数', dataIndex: 'session_count', width: 140 },
    ],
  },
  country: {
    api: '/api/getCountryStatsList',
    columns: [
      { title: '国家/地区', dataIndex: 'country', width: 220 },
      { title: 'IP数量', dataIndex: 'ip_count', width: 120 },
      { title: '数据包数', dataIndex: 'total_packets', width: 140 },
      { title: '总字节数', dataIndex: 'total_bytes', width: 140 },
      { title: '会话数', dataIndex: 'session_count', width: 140 },
    ],
  },
};

function StatsPage(props) {
  const statsType = props.match.params.type || 'ip';
  const config = statsConfig[statsType] || statsConfig.ip;

  const [loading, setLoading] = useState(false);
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(30);
  const [total, setTotal] = useState(0);
  const [dataList, setDataList] = useState([]);

  const columns = useMemo<TableColumnProps[]>(() => config.columns, [config]);

  const loadData = async () => {
    setLoading(true);
    try {
      const values = await apiFetchData(config.api, {
        pageSize,
        pageNum: currentPage,
      });
      setDataList(values.data || []);
      setTotal(values.total || 0);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    setCurrentPage(1);
  }, [statsType]);

  useEffect(() => {
    loadData();
  }, [statsType, currentPage, pageSize]);

  return (
    <div>
      <Table
        columns={columns}
        data={dataList}
        loading={loading}
        pagination={false}
        rowKey={(record, index) => `${statsType}-${record.ip || record.proto || record.country || index}`}
        scroll={{ y: 600, x: '100%' }}
      />
      <Pagination
        current={currentPage}
        showTotal
        sizeCanChange
        total={total}
        pageSize={pageSize}
        onChange={(page) => setCurrentPage(page)}
        onPageSizeChange={(size) => setPageSize(size)}
        style={{ marginTop: 16, textAlign: 'right', justifyContent: 'flex-end' }}
      />
    </div>
  );
}

export default StatsPage;
