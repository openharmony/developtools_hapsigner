/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef SIGNATRUETOOLS_THREAD_POOL_H
#define SIGNATRUETOOLS_THREAD_POOL_H

#include <vector>
#include <queue>
#include <memory>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <future>
#include <functional>
#include <stdexcept>

#define TASK_NUM (std::thread::hardware_concurrency())

namespace OHOS {
namespace SignatureTools {
namespace Uscript {
class ThreadPool {
public:
    ThreadPool(size_t threads)
        : stop(false)
    {
        for (size_t i = 0; i < threads; ++i)
            workers.emplace_back([this] {
            std::function<void()> task;
            std::unique_lock<std::mutex> lock(queue_mutex);
            while (!(stop && tasks.empty())) {
                condition.wait(lock, [this] { return stop || !tasks.empty(); });
                if (stop && tasks.empty())
                    return;
                task = std::move(tasks.front());
                tasks.pop();
                lock.unlock();
                task();
                lock.lock();
                condition_max.notify_one();
            }
        });
    }

    template<class F, class... Args>
    auto Enqueue(F&& f, Args&& ... args)
        -> std::future<typename std::result_of<F(Args...)>::type>
    {
        using returnType = typename std::result_of<F(Args...)>::type;
        auto task = std::make_shared< std::packaged_task<returnType()> >(
            std::bind(std::forward<F>(f), std::forward<Args>(args)...)
        );
        std::future<returnType> res = task->get_future();
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            // don't allow enqueueing after stopping the pool
            if (stop)
                throw std::runtime_error("enqueue on stopped ThreadPool");
            while (stop == false && tasks.size() >= TASK_NUM)
                condition_max.wait(lock);
            tasks.emplace([task] () { (*task)(); });
            condition.notify_one();
        }
        return res;
    }

    ~ThreadPool()
    {
        if (stop == false) {
            {
                std::unique_lock<std::mutex> lock(queue_mutex);
                stop = true;
            }
            condition.notify_all();
            for (std::thread& worker : workers)
                worker.join();
        }
    }

private:
    // need to keep track of threads so we can join them
    std::vector< std::thread > workers;
    // the task queue
    std::queue< std::function<void()> > tasks;
    // synchronization
    std::mutex queue_mutex;
    std::condition_variable condition;
    std::condition_variable condition_max;
    bool stop;
};
} // namespace Uscript
} // namespace SignatureTools
} // namespace OHOS
#endif