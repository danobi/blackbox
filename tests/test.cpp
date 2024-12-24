#include <blackbox.h>
#include <gtest/gtest.h>

#include <atomic>
#include <csignal>
#include <thread>

using namespace std::chrono_literals;

namespace {

std::atomic_bool signal_nesting_error;
std::atomic_bool signal_thread_started;

void SignalHandler(int signal) {
  if (signal == SIGUSR1) {
    if (blackbox::write("test") == -EDEADLK) {
      signal_nesting_error.store(true);
    }
    return;
  }

  std::ostream dummy(0);
  if (signal == SIGUSR2) {
    if (blackbox::dump(dummy) == -EDEADLK) {
      signal_nesting_error.store(true);
    }
  }
}

enum blackbox_ops {
  OP_WRITE,
  OP_DUMP,
};

void SignalHandlerNesting(blackbox_ops main_op, blackbox_ops sig_op) {
  signal_nesting_error.store(false);
  signal_thread_started.store(false);

  int signal = sig_op == OP_WRITE ? SIGUSR1 : SIGUSR2;

  std::jthread thread([&] {
    sigset_t signal_set;
    sigemptyset(&signal_set);
    sigaddset(&signal_set, signal);
    EXPECT_EQ(::pthread_sigmask(SIG_UNBLOCK, &signal_set, nullptr), 0);
    struct sigaction sa;
    sa.sa_handler = SignalHandler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    EXPECT_EQ(::sigaction(signal, &sa, nullptr), 0);

    signal_thread_started.store(true);

    while (!signal_nesting_error.load()) {
      switch (main_op) {
	case OP_WRITE: {
	  blackbox::write("test");
	  break;
	}
	case OP_DUMP: {
	  std::ostream dummy(0);
	  blackbox::dump(dummy);
	  break;
	}
      }
    }
  });

  while (!signal_thread_started.load());

  while (!signal_nesting_error.load()) {
    ::pthread_kill(thread.native_handle(), signal);
    std::this_thread::sleep_for(1ms);
  }
}

}  // namespace

TEST(blackbox, signal_nesting_dump_dump) {
  SignalHandlerNesting(OP_DUMP, OP_DUMP);
}

TEST(blackbox, signal_nesting_dump_write) {
  SignalHandlerNesting(OP_DUMP, OP_WRITE);
}

TEST(blackbox, signal_nesting_write_dump) {
  SignalHandlerNesting(OP_WRITE, OP_DUMP);
}

TEST(blackbox, signal_nesting_write_write) {
  SignalHandlerNesting(OP_WRITE, OP_WRITE);
}

int main(int argc, char *argv[]) {
  ::testing::InitGoogleTest(&argc, argv);
  blackbox::init();
  for (int i = 0; i < 100; i++) {
    blackbox::write("key=1", "value=1");
  }

  return RUN_ALL_TESTS();
}
