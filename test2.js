const arr = [10, 20, 30, 40, 50];
const buffer = 0;
arr[buffer >>> 2] = 100;  // buffer를 1비트 오른쪽으로 시프트한 값을 인덱스로 사용하여 값 지정
console.log(arr);  // [10, 20, 30, 40, 100]