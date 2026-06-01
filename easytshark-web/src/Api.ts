import React, { useEffect, useState } from 'react';
import axios from 'axios';

const baseUrl = "http://127.0.0.1:8080"



export const apiPost = async (url, data = {}, config = {}) => {
  try {
    // 发送 POST 请求
    const response = await axios.post(baseUrl + url, data, config);

    // 返回响应数据
    return response.data;
  } catch (error) {
    // 如果请求失败，抛出错误
    console.error('Error in postData:', error);
    throw error; // 可以选择抛出错误或返回一个默认值
  }
};

export const apiUploadFile = async (url, file, config = {}) => {
  try {
    const formData = new FormData();
    formData.append('file', file);
    const response = await axios.post(baseUrl + url, formData, {
      ...config,
      headers: {
        'Content-Type': 'multipart/form-data',
        ...(config as any).headers,
      },
    });

    return response.data;
  } catch (error) {
    console.error('Error in uploadFile:', error);
    throw error;
  }
};

export const apiGet = async (url) => {
  try {
    // 发送 POST 请求
    const response = await axios.get(baseUrl + url);

    // 返回响应数据
    return response.data;
  } catch (error) {
    // 如果请求失败，抛出错误
    console.error('Error in postData:', error);
    throw error; // 可以选择抛出错误或返回一个默认值
  }
};


export const apiFetchData = async (url, data = {}, config = {}) => {
  try {
    
    let _url = url
    if (data["pageNum"] != undefined && data["pageSize"] != undefined) {
      _url = url + '?pageSize=' + data["pageSize"] + "&pageNum=" + data["pageNum"]
    }

    // 发送 POST 请求
    const response = await axios.post(baseUrl + _url, data, config);

    // 返回响应数据
    return response.data;
  } catch (error) {
    // 如果请求失败，抛出错误
    console.error('Error in postData:', error);
    throw error; // 可以选择抛出错误或返回一个默认值
  }
};
