import java.util.concurrent.SynchronousQueue;

public class Queue {

    // program that has a producer and a consumer thread
    // they share a queue
    // items on the queue are invalid after 1 second
    // crash if consumer tries to access invalid ite
    // use Java queues

    record WorkItem(long timestamp, int value) {
        public boolean isValid() {
            return System.currentTimeMillis() - timestamp < ITEM_LIFETIME;
        }
    }

    private static final int ITEM_LIFETIME = 100;

    private final SynchronousQueue<WorkItem> queue;

    public Queue() {
        this.queue = new SynchronousQueue<>();
    }

    public void run() {
        Thread producer = new Thread(() -> {
            while (true) {
                produce((int) (Math.random() * 100));
                try {
                    Thread.sleep(10);
                } catch (InterruptedException e) {
                    throw new RuntimeException(e);
                }
            }
        });
        Thread consumer = new Thread(() -> {
            while (true) {
                consume();
                try {
                    Thread.sleep(10);
                } catch (InterruptedException e) {
                    throw new RuntimeException(e);
                }
            }
        });
        producer.setName("Producer");
        consumer.setName("Consumer");
        producer.start();
        consumer.start();
        try {
            producer.join();
            consumer.join();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    public void produce(int value) {
        WorkItem item = new WorkItem(System.currentTimeMillis(), value);
        try {
            queue.put(item);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    public int consume() {
        WorkItem item = null;
        try {
            item = queue.take();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        if (!item.isValid()) {
            System.err.println("Item is invalid!");
            System.exit(1);
        }
        return item.value();
    }

    public static void main(String[] args) {
        new Queue().run();
    }
}