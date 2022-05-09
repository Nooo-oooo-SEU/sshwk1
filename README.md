# sshwk1

### Detector_IAT.py Requirement 
- 修改Detector.py, 通过Import Address Table表中导入的函数名来进行恶意软件检测
- FeatureHasher的参数改为1000 


### Detector_PEHeader.py Requirement 
- 修改Detector.py, 通过PE Header中 IMAGE_OPTIONAL_HEADER32 结构中所有成员 (DataDirectory成员除外)作为特征来进行恶意软件检测 
- 不使用FeatureHasher 