package util

import (
	"fmt"
	"log"
	"math"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/spf13/viper"
	ort "github.com/yalue/onnxruntime_go"
)

var (
	ortInitialized = false

	// AI 推理会话与输入/输出张量只初始化一次，全局复用，
	// 避免每个数据包都重新读取模型文件、重建 session。
	aiSession      *ort.AdvancedSession
	aiInputTensor  *ort.Tensor[float32]
	aiOutputTensor *ort.Tensor[float32]
	aiReady        bool
	aiMu           sync.Mutex
)

func init() {
	libPath := viper.GetString("ortlib_path")

	if libPath != "" {
		log.Printf("Using ONNX Runtime shared library: %s", libPath)
		ort.SetSharedLibraryPath(libPath)
		if err := ort.InitializeEnvironment(); err != nil {
			log.Printf("Failed to initialize ONNX Runtime: %v", err)
			return
		}
		ortInitialized = true
		log.Println("ONNX Runtime initialized successfully")
	} else {
		// Try to initialize with default system library
		if err := ort.InitializeEnvironment(); err != nil {
			log.Printf("ONNX Runtime not initialized. AI detection will be disabled.")
			log.Printf("To enable AI detection, install ONNX Runtime and set 'ortlib_path' in config.toml")
			return
		}
		ortInitialized = true
		log.Println("ONNX Runtime initialized with system library")
	}

	// 模型只加载一次，构建可复用的推理会话；失败则优雅降级，不影响主程序运行。
	if err := initSession(); err != nil {
		log.Printf("[AI-Local] Failed to load model, AI detection disabled: %v", err)
	}
}

// initSession 加载 ONNX 模型，并创建可复用的会话与输入/输出张量。
// 会话在程序生命周期内长期持有，后续推理直接复用，无需重复加载模型。
func initSession() error {
	modelPath := viper.GetString("model_path")
	if modelPath == "" {
		return fmt.Errorf("model_path is not set")
	}

	// 输入张量 shape: (1, 1, 8, 8)，输出张量 shape: (1, 2)
	inputTensor, err := ort.NewEmptyTensor[float32](ort.NewShape(1, 1, 8, 8))
	if err != nil {
		return fmt.Errorf("create input tensor: %w", err)
	}
	outputTensor, err := ort.NewEmptyTensor[float32](ort.NewShape(1, 2))
	if err != nil {
		inputTensor.Destroy()
		return fmt.Errorf("create output tensor: %w", err)
	}

	session, err := ort.NewAdvancedSession(modelPath,
		[]string{"input"}, []string{"output"},
		[]ort.Value{inputTensor}, []ort.Value{outputTensor}, nil)
	if err != nil {
		inputTensor.Destroy()
		outputTensor.Destroy()
		return fmt.Errorf("create ONNX session: %w", err)
	}

	aiInputTensor = inputTensor
	aiOutputTensor = outputTensor
	aiSession = session
	aiReady = true
	log.Printf("[AI-Local] Model loaded and session ready: %s", modelPath)
	return nil
}

// Check 对单个数据包做推理，返回“异常概率”[0,1] 以及模型是否可用（ok）。
// 当模型未就绪或推理失败时返回 (0, false)，由调用方决定如何降级。
func Check(packet gopacket.Packet) (float32, bool) {
	if !ortInitialized || !aiReady {
		return 0, false
	}

	image := PreprocessPacket(packet)

	// ONNX 会话非线程安全，且复用同一组张量，这里串行化访问。
	aiMu.Lock()
	defer aiMu.Unlock()

	// 复用输入张量：直接写入其底层缓冲，避免每次分配新张量。
	copy(aiInputTensor.GetData(), image)

	if err := aiSession.Run(); err != nil {
		// 单次推理失败时优雅降级，仅记录日志，绝不终止整个进程。
		log.Printf("[AI-Local] Model inference failed: %v", err)
		return 0, false
	}

	result := aiOutputTensor.GetData()
	if len(result) < 2 {
		log.Printf("[AI-Local] Unexpected model output length: %d", len(result))
		return 0, false
	}

	// 标签方向：result[0]=异常、result[1]=正常（与原实现相反）。
	// 依据是异常检测中异常应为少数类，而占多数（~91%）的应为正常。
	// 注意：该方向尚未用带标签的数据集最终确认。
	return softmax2(result[1], result[0]), true
}

// softmax2 计算二分类的第二类（异常）概率，做了数值稳定处理。
func softmax2(normal, anomaly float32) float32 {
	max := normal
	if anomaly > max {
		max = anomaly
	}
	e0 := math.Exp(float64(normal - max))
	e1 := math.Exp(float64(anomaly - max))
	return float32(e1 / (e0 + e1))
}

// packet转换为张量的函数
func PreprocessPacket(packet gopacket.Packet) []float32 {
	// 匿名化
	raw := AnonymizePacket(packet)

	// 保留前64字节，不足补0
	fixed := make([]byte, 64)
	copy(fixed, raw)

	// 转换为 float32 并归一化
	floatData := make([]float32, 64)
	for i := 0; i < 64; i++ {
		floatData[i] = float32(fixed[i]) / 255.0
	}

	// 标准化,由模型决定
	var mean float32
	var std float32
	mean = 0.2515
	std = 0.3778

	for i := range floatData {
		floatData[i] = (floatData[i] - mean) / std
	}

	return floatData
}

// 匿名化函数
func AnonymizePacket(packet gopacket.Packet) []byte {
	data := packet.Data()
	newData := make([]byte, len(data))
	copy(newData, data)

	// 匿名化 MAC 地址
	if len(newData) >= 14 {
		copy(newData[0:6], make([]byte, 6))  // dst MAC
		copy(newData[6:12], make([]byte, 6)) // src MAC
	}

	if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		//处理ipv4
		ipHeaderOffset := 14                                                // Ethernet header
		copy(newData[ipHeaderOffset+12:ipHeaderOffset+16], make([]byte, 4)) // src IP
		copy(newData[ipHeaderOffset+16:ipHeaderOffset+20], make([]byte, 4)) // dst IP

	} else if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
		//处理ipv6，  //好像输入的张量大小容不下ipv6
		ipHeaderOffset := 14                                                 // Ethernet header
		copy(newData[ipHeaderOffset+8:ipHeaderOffset+24], make([]byte, 16))  // src IP
		copy(newData[ipHeaderOffset+24:ipHeaderOffset+40], make([]byte, 16)) // dst IP
	}

	return newData
}
