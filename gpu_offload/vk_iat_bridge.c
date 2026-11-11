#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <vulkan/vulkan.h>

int main() {
    int fd = open("/dev/shm/zero_shield_ring", O_RDWR);
    if (fd < 0) {
        perror("open /dev/shm/zero_shield_ring");
        return 1;
    }
    void* shm_ptr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

    VkInstance inst;
    VkInstanceCreateInfo ici = { .sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO };
    vkCreateInstance(&ici, NULL, &inst);

    uint32_t gpu_cnt = 0;
    vkEnumeratePhysicalDevices(inst, &gpu_cnt, NULL);
    VkPhysicalDevice gpus[8];
    vkEnumeratePhysicalDevices(inst, &gpu_cnt, gpus);

    VkPhysicalDevice gpu = VK_NULL_HANDLE;
    VkPhysicalDeviceProperties props;
    VkPhysicalDevice fallback_cpu = VK_NULL_HANDLE;
    VkPhysicalDeviceProperties fallback_props;
    for (uint32_t i = 0; i < gpu_cnt; i++) {
        VkPhysicalDeviceFeatures feats;
        vkGetPhysicalDeviceFeatures(gpus[i], &feats);
        vkGetPhysicalDeviceProperties(gpus[i], &props);
        if (feats.shaderInt64) {
            if (props.deviceType != VK_PHYSICAL_DEVICE_TYPE_CPU) {
                gpu = gpus[i];
                break;
            } else if (fallback_cpu == VK_NULL_HANDLE) {
                fallback_cpu = gpus[i];
                fallback_props = props;
            }
        }
    }
    if (gpu == VK_NULL_HANDLE && fallback_cpu != VK_NULL_HANDLE) {
        gpu = fallback_cpu;
        props = fallback_props;
    }

    uint32_t q_cnt = 0;
    vkGetPhysicalDeviceQueueFamilyProperties(gpu, &q_cnt, NULL);
    VkQueueFamilyProperties qprops[8];
    vkGetPhysicalDeviceQueueFamilyProperties(gpu, &q_cnt, qprops);
    uint32_t q_idx = 0;
    for (uint32_t i = 0; i < q_cnt; i++) {
        if (qprops[i].queueFlags & VK_QUEUE_COMPUTE_BIT) { q_idx = i; break; }
    }

    float prio = 1.0f;
    VkDeviceQueueCreateInfo qci = { .sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO, .queueFamilyIndex = q_idx, .queueCount = 1, .pQueuePriorities = &prio };
    VkPhysicalDeviceFeatures req_feats = { .shaderInt64 = VK_TRUE };
    VkDeviceCreateInfo dci = { .sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO, .queueCreateInfoCount = 1, .pQueueCreateInfos = &qci, .pEnabledFeatures = &req_feats };
    VkDevice dev;
    vkCreateDevice(gpu, &dci, NULL, &dev);
    VkQueue queue;
    vkGetDeviceQueue(dev, q_idx, 0, &queue);

    VkBuffer buf;
    VkBufferCreateInfo bci = { .sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO, .size = 4096, .usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT };
    vkCreateBuffer(dev, &bci, NULL, &buf);

    VkMemoryRequirements mem_req;
    vkGetBufferMemoryRequirements(dev, buf, &mem_req);
    VkPhysicalDeviceMemoryProperties mprops;
    vkGetPhysicalDeviceMemoryProperties(gpu, &mprops);
    uint32_t m_idx = 0;
    VkMemoryPropertyFlags want = VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT;
    for (uint32_t i = 0; i < mprops.memoryTypeCount; i++) {
        if ((mem_req.memoryTypeBits & (1 << i)) && (mprops.memoryTypes[i].propertyFlags & want) == want) { m_idx = i; break; }
    }

    VkDeviceMemory mem;
    VkMemoryAllocateInfo mai = { .sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO, .allocationSize = mem_req.size, .memoryTypeIndex = m_idx };
    vkAllocateMemory(dev, &mai, NULL, &mem);
    vkBindBufferMemory(dev, buf, mem, 0);

    void* ptr = NULL;
    vkMapMemory(dev, mem, 0, 4096, 0, &ptr);
    memcpy(ptr, shm_ptr, 2048);
    uint32_t* alert = (uint32_t*)((uint8_t*)ptr + 2048);
    float* entropy = (float*)((uint8_t*)ptr + 2052);
    *alert = 0;
    *entropy = 0.0f;

    FILE* f = fopen("gpu_offload/shield_iat.spv", "rb");
    if (!f) f = fopen("shield_iat.spv", "rb");
    fseek(f, 0, SEEK_END); long fsize = ftell(f); rewind(f);
    uint32_t* spv = malloc(fsize); fread(spv, 1, fsize, f); fclose(f);

    VkShaderModule smod;
    VkShaderModuleCreateInfo smci = { .sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO, .codeSize = fsize, .pCode = spv };
    vkCreateShaderModule(dev, &smci, NULL, &smod);

    VkDescriptorSetLayoutBinding bind = { .binding = 0, .descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, .descriptorCount = 1, .stageFlags = VK_SHADER_STAGE_COMPUTE_BIT };
    VkDescriptorSetLayout dsl;
    VkDescriptorSetLayoutCreateInfo dslci = { .sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO, .bindingCount = 1, .pBindings = &bind };
    vkCreateDescriptorSetLayout(dev, &dslci, NULL, &dsl);

    VkPipelineLayout pl;
    VkPipelineLayoutCreateInfo plci = { .sType = VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO, .setLayoutCount = 1, .pSetLayouts = &dsl };
    vkCreatePipelineLayout(dev, &plci, NULL, &pl);

    VkComputePipelineCreateInfo cpci = {
        .sType = VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO,
        .stage = { .sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO, .stage = VK_SHADER_STAGE_COMPUTE_BIT, .module = smod, .pName = "main" },
        .layout = pl
    };
    VkPipeline pipe;
    vkCreateComputePipelines(dev, VK_NULL_HANDLE, 1, &cpci, NULL, &pipe);

    VkDescriptorPoolSize dps = { .type = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, .descriptorCount = 1 };
    VkDescriptorPool dp;
    VkDescriptorPoolCreateInfo dpci = { .sType = VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO, .maxSets = 1, .poolSizeCount = 1, .pPoolSizes = &dps };
    vkCreateDescriptorPool(dev, &dpci, NULL, &dp);

    VkDescriptorSet ds;
    VkDescriptorSetAllocateInfo dsai = { .sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO, .descriptorPool = dp, .descriptorSetCount = 1, .pSetLayouts = &dsl };
    vkAllocateDescriptorSets(dev, &dsai, &ds);

    VkDescriptorBufferInfo dbi = { .buffer = buf, .offset = 0, .range = 4096 };
    VkWriteDescriptorSet wds = { .sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET, .dstSet = ds, .dstBinding = 0, .descriptorCount = 1, .descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, .pBufferInfo = &dbi };
    vkUpdateDescriptorSets(dev, 1, &wds, 0, NULL);

    VkCommandPool cp;
    VkCommandPoolCreateInfo cp_info = { .sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO, .queueFamilyIndex = q_idx };
    vkCreateCommandPool(dev, &cp_info, NULL, &cp);

    VkCommandBuffer cb;
    VkCommandBufferAllocateInfo cbai = { .sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO, .commandPool = cp, .level = VK_COMMAND_BUFFER_LEVEL_PRIMARY, .commandBufferCount = 1 };
    vkAllocateCommandBuffers(dev, &cbai, &cb);

    VkCommandBufferBeginInfo cbbi = { .sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO };
    vkBeginCommandBuffer(cb, &cbbi);
    vkCmdBindPipeline(cb, VK_PIPELINE_BIND_POINT_COMPUTE, pipe);
    vkCmdBindDescriptorSets(cb, VK_PIPELINE_BIND_POINT_COMPUTE, pl, 0, 1, &ds, 0, NULL);
    vkCmdDispatch(cb, 1, 1, 1);
    vkEndCommandBuffer(cb);

    VkSubmitInfo si = { .sType = VK_STRUCTURE_TYPE_SUBMIT_INFO, .commandBufferCount = 1, .pCommandBuffers = &cb };
    vkQueueSubmit(queue, 1, &si, VK_NULL_HANDLE);
    vkQueueWaitIdle(queue);

    // Записываем оба вердикта GPU обратно в общую DDR-страницу для Rust-ядра
    *(uint32_t*)((uint8_t*)shm_ptr + 2048) = *alert;
    *(float*)((uint8_t*)shm_ptr + 2052) = *entropy;

    const char* verdict = (*entropy > 2.5f) ? "HIGH ENTROPY (Dynamic Padding / Hysteria2 Suspected)" : "DETERMINISTIC FLOW (Low IAT Entropy)";

    printf("[Rust no_std -> /dev/shm -> Vulkan %s]\n", props.deviceName);
    printf("  1. IAT Jitter Spike Alerts: %u (Expected: 4)\n", *alert);
    printf("  2. Shannon IAT Entropy (H): %.4f bits (Max 4.0000)\n", *entropy);
    printf("  3. Spectral Shield Verdict: %s\n", verdict);

    return 0;
}
