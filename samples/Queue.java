import java.util.concurrent.ConcurrentLinkedDeque;

public class Queue {

    record WorkItem(long timestamp, int value) {
        public boolean isValid() {
            return System.currentTimeMillis() - timestamp < ITEM_LIFETIME;
        }
    }

    private static final int ITEM_LIFETIME = 1000;

    private final ConcurrentLinkedDeque<WorkItem> queue;

    public Queue() {
        this.queue = new ConcurrentLinkedDeque<>();
    }

    public void run() {
        var producer = new Thread(() -> {
            while (true) {
                produce((int) (Math.random() * 100));
                sleep(20);
            }
        });
        producer.setName("Producer");
        producer.start();
        var consumer = new Thread(() -> {
            while (true) {
                consume();
                sleep(10);
            }
        });
        consumer.setName("Consumer");
        consumer.start();
        sleep(-1);
    }

    public void produce(int value) {
        queue.push(new WorkItem(System.currentTimeMillis(), value));
    }

    public int consume() {
        WorkItem item = queue.poll();
        if (item == null) {
            return -1;
        }
        if (!item.isValid()) {
            System.err.println("Item is invalid! time " + (System.currentTimeMillis() - item.timestamp));
            System.exit(1);
        }
        return item.value();
    }

    public static void main(String[] args) {
        new Queue().run();
    }

    //<editor-fold desc="Boilerplate">
    void sleep(long millis) {
        try {
            Thread.sleep(millis == -1 ? Long.MAX_VALUE : millis);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }
    //</editor-fold>
}